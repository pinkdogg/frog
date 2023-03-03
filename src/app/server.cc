#include <iostream>
#include "SSLConnection.h"
#include "ServerOptThread.h"
#include <boost/thread/thread.hpp>
#include <map>
#include <filesystem>
#include <fstream>

#include <sgx_urts.h>

#include "EnclaveBudget_u.h"
#include "EnclaveCompute_u.h"

#define ENCLAVE_BUDGET_PATH "../lib/libenclave_budget.signed.so"
#define ENCLAVE_COMPUTE_PATH "../lib/libenclave_compute.signed.so"

sgx_enclave_id_t budget_enclave_id = 0, compute_enclave_id = 0;

void print_string_ocall(const char *str) {
    printf("%s", str);
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

  // load files in directory ./data/gwas/
  const std::filesystem::path gwas{"./data/gwas"};

  uint8_t* ciphertext = (uint8_t*)malloc(kREADSIZE);
  uint32_t len;
  for(auto const& dir_entry : std::filesystem::directory_iterator(gwas)) {
    std::cout << dir_entry.path() << std::endl;
    std::ifstream file(dir_entry.path(), std::ios::in | std::ios::binary);

    while(true) {
      file.read((char*)ciphertext, kREADSIZE);
      len = file.gcount();
      if(len > 0) {
        ecall_decrypt_process(compute_enclave_id, (uint8_t*)ciphertext, len);
      } else {
        break;
      }
    }
  }
  free(ciphertext);
}
int main()
{
  initialize_enclave();

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