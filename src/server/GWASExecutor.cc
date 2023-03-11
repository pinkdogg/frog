#include "GWASExecutor.h"

#include <cstring>
#include <iostream>

#include "EnclaveCompute_u.h"
#include "json11.h"

using namespace json11;

extern sgx_enclave_id_t compute_enclave_id;

GWASExecutor::GWASExecutor(uint8_t* paras, uint32_t parasLen) {
  std::string err;
  Json parasJson = Json::parse(std::string((char*)paras, parasLen), err);
  ld_para_1 = parasJson["LD"].array_items()[0].int_value();
  ld_para_2 = parasJson["LD"].array_items()[1].int_value();
  hwe_para = parasJson["HWE"].int_value();
  catt_para = parasJson["CATT"].int_value();
  fet_para = parasJson["FET"].int_value();

  std::cout << "LD:" << ld_para_1 << " " << ld_para_2 << std::endl;
  std::cout << "HWE:" << hwe_para << std::endl;
  std::cout << "CATT:" << catt_para << std::endl;
  std::cout << "FET:" << fet_para << std::endl;
}

GWASExecutor::~GWASExecutor() {}

void GWASExecutor::execute(uint8_t** result, uint32_t& resultSize) {
  sgx_status_t status;
  uint32_t ret_status;

  int ret_ld, ret_hwe, ret_catt, ret_fet;

  status = ecall_hwe(compute_enclave_id, &ret_status, hwe_para, &ret_hwe);
  if (status != SGX_SUCCESS || ret_status != 0) {
    //   printf("failed to calculate HWE.\n");
    ret_hwe = -1;
  }

  status =
      ecall_ld(compute_enclave_id, &ret_status, ld_para_1, ld_para_2, &ret_ld);
  if (status != SGX_SUCCESS || ret_status != 0) {
    //   printf("failed to calculate LD.\n");
    ret_ld = -1;
  }

  status = ecall_catt(compute_enclave_id, &ret_status, catt_para, &ret_catt);
  if (status != SGX_SUCCESS || ret_status != 0) {
    //   printf("failed to calculate CATT.\n");
    ret_catt = -1;
  }

  status = ecall_fet(compute_enclave_id, &ret_status, fet_para, &ret_fet);
  if (status != SGX_SUCCESS || ret_status != 0) {
    //   printf("failed to calculate FET.\n");
    ret_fet = -1;
  }

  printf("HWE Result = %d\n", ret_hwe);
  printf("LD Result = %d\n", ret_ld);
  printf("CATT Result = %d\n", ret_catt);
  printf("FET Result = %d\n", ret_fet);

  Json resultJson = Json::object{
      {"LD", ret_ld}, {"HWE", ret_hwe}, {"CATT", ret_catt}, {"FET", ret_fet}};
  std::string resultStr = resultJson.dump();
  resultSize = resultStr.size();
  *result = (uint8_t*)malloc(resultSize);
  memcpy(*result, resultStr.c_str(), resultSize);
}