#include <map>
#include <filesystem>
#include <csignal>
#include "SSLConnection.h"
#include "ServerOptThread.h"
#include "CryptoPrimitive.h"
#include "EnclaveBudget_u.h"
#include "EnclaveCompute_u.h"
#include "server.h"

#define ENCLAVE_BUDGET_PATH "../src/Enclave/EnclaveBudget/libenclave_budget.signed.so"
#define ENCLAVE_COMPUTE_PATH "../src/Enclave/EnclaveCompute/libenclave_compute.signed.so"

#define BUDGET_SEALED_DATA_FILE "sealed_budget_data"
#define COMPUTE_SEALED_DATA_FILE "sealed_compute_data"
#define DATA_DIR "./data/gwas"

sgx_enclave_id_t budget_enclave_id = 0, compute_enclave_id = 0;
CryptoPrimitive cryptoPrimitive(kSHA256, kAES_256_GCM);

int ocall_query_budget(const char* strFileNameHash) {
  int ret = 1;
  sgx_status_t status = ecall_query_budget(budget_enclave_id, &ret, strFileNameHash);
  if(status != SGX_SUCCESS) {
    return 1;
  }
  return ret;
}

void load_data(char* dirPath) {
  const std::filesystem::path gwas{dirPath};
  uint8_t* ciphertext = (uint8_t*)malloc(kREADSIZE);
  uint32_t len;

  for(auto const& dir_entry : std::filesystem::directory_iterator(gwas)) {
    std::cout << "loading file: " << dir_entry.path() << std::endl;
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

  // unseal data
  ComputeUnSealData(compute_enclave_id, COMPUTE_SEALED_DATA_FILE);
  BudgetUnSealData(budget_enclave_id, BUDGET_SEALED_DATA_FILE);

  // load files in directory ./data/gwas/
  load_data(DATA_DIR);
}

void signalHandler(int sigNum) {
  std::cout << "Sealing data." << std::endl;
  // Get the sealed data size of compute enclave
  uint32_t sealed_data_size = 0;
  sgx_status_t ret = ecall_compute_get_sealed_data_size(compute_enclave_id, &sealed_data_size);
  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  sgx_status_t retval;
  ret = ecall_compute_seal_data(compute_enclave_id, &retval, temp_sealed_buf, sealed_data_size);
  // Save to file
  write_buf_to_file(COMPUTE_SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0);
  free(temp_sealed_buf);
  sgx_destroy_enclave(compute_enclave_id);

  // Get the sealed data size of budget enclave
  sealed_data_size = 0;
  ret = ecall_budget_get_sealed_data_size(budget_enclave_id, &sealed_data_size);
  temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  ret = ecall_budget_seal_data(budget_enclave_id, &retval, temp_sealed_buf, sealed_data_size);
  // Save to file
  write_buf_to_file(BUDGET_SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0);
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