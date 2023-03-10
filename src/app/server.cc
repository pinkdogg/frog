#include <iostream>
#include "SSLConnection.h"
#include "ServerOptThread.h"
#include "CryptoPrimitive.h"
#include <map>
#include <filesystem>
#include <fstream>
#include <csignal>

#include <sgx_urts.h>

#include "EnclaveBudget_u.h"
#include "EnclaveCompute_u.h"

#define ENCLAVE_BUDGET_PATH "../src/Enclave/EnclaveBudget/libenclave_budget.signed.so"
#define ENCLAVE_COMPUTE_PATH "../src/Enclave/EnclaveCompute/libenclave_compute.signed.so"

#define BUDGET_SEALED_DATA_FILE "sealed_budget_data"
#define COMPUTE_SEALED_DATA_FILE "sealed_compute_data"

sgx_enclave_id_t budget_enclave_id = 0, compute_enclave_id = 0;
CryptoPrimitive cryptoPrimitive(kSHA256, kAES_256_GCM);

void print_string_ocall(const char *str) {
    printf("%s", str);
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

void initialize_enclave() {
    int update = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t status;
    uint32_t ret_status;

  // load budget and compute enclaves
  if (SGX_SUCCESS != sgx_create_enclave(ENCLAVE_BUDGET_PATH, SGX_DEBUG_FLAG, &token, &update, &budget_enclave_id, NULL)
      || SGX_SUCCESS != sgx_create_enclave(ENCLAVE_COMPUTE_PATH, SGX_DEBUG_FLAG, &token, &update, &compute_enclave_id, NULL)) {
      printf("failed to load enclave.\n");
      exit(EXIT_FAILURE);
  }
  printf("succeed to load enclaves.\n");

  // Read the sealed blob from the file
  size_t fsize = get_file_size("enclave_compute");
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if(read_file_to_buf("enclave_compute", temp_buf, fsize)) {
    // Unseal the sealed blob
    sgx_status_t retval;
    sgx_status_t ret = ecall_unseal_data(compute_enclave_id, &retval, temp_buf, fsize);
  }
  free(temp_buf);

  // load files in directory ./data/gwas/
  const std::filesystem::path gwas{"./data/gwas"};

  uint8_t* ciphertext = (uint8_t*)malloc(kREADSIZE);
  uint32_t len;

  for(auto const& dir_entry : std::filesystem::directory_iterator(gwas)) {
    std::cout << dir_entry.path() << std::endl;
    std::ifstream file(dir_entry.path(), std::ios::in | std::ios::binary);

    std::string fileName;
    size_t i = (dir_entry.path()).string().rfind('/');
    if(i != std::string::npos) {
      fileName = dir_entry.path().string().substr(i+1);
    } else {
      fileName = dir_entry.path().string();
    }

    while(true) {
      file.read((char*)ciphertext, kREADSIZE);
      len = file.gcount();
      if(len > 0) {
        ecall_decrypt_process(compute_enclave_id, fileName.c_str(), (uint8_t*)ciphertext, len);
      } else {
        break;
      }
    }
  }
  free(ciphertext);
}

void signalHandler(int sigNum) {
  std::cout << "Sealing data." << std::endl;
  
  
  // Get the sealed data size
  uint32_t sealed_data_size = 0;
  sgx_status_t ret = ecall_get_sealed_data_size(compute_enclave_id, &sealed_data_size);
  
  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  sgx_status_t retval;
  ret = ecall_seal_data(compute_enclave_id, &retval, temp_sealed_buf, sealed_data_size);
  
  // Save the sealed blob
  (write_buf_to_file("enclave_compute", temp_sealed_buf, sealed_data_size, 0) == false);

  free(temp_sealed_buf);
  sgx_destroy_enclave(compute_enclave_id);

  std::cout << "Sealing data succeeded." << std::endl;

  exit(sigNum);
}

int main()
{
  initialize_enclave();
  signal(SIGINT, signalHandler);

  std::shared_ptr<SSLConnection> sslConnection;
  std::shared_ptr<ServerOptThread> serverOptThread;
  while(true) {
    printf("Server:waiting the request from the client.\n");
    sslConnection = std::make_shared<SSLConnection>("127.0.0.1", 1666, kSERVERSIDE);
    if(!sslConnection->ListenSSL()) {
      fprintf(stderr, "Server:SSLConnection listen error.\n");
      break;
    }
    std::shared_ptr<ServerOptThread> serverOptThread = std::make_shared<ServerOptThread>(sslConnection);
    serverOptThread->Run();
  }

  sgx_destroy_enclave(budget_enclave_id);
  sgx_destroy_enclave(compute_enclave_id);
  return 0;
}