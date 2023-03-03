#include "GWASExecutor.h"
#include <iostream>
#include "json11.h"
#include <cstring>

#include "EnclaveCompute_u.h"

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

bool GWASExecutor::execute(uint8_t** result, uint32_t& resultSize) {
  sgx_status_t status;
  uint32_t ret_status;

  char ret_ld, ret_hwe, ret_catt, ret_fet;

  status = ecall_hwe(compute_enclave_id, &ret_status, hwe_para, &ret_hwe, 1);
  if(status != SGX_SUCCESS || ret_status != 0) {
      printf("failed to calculate HWE.\n");
      return false;
  } 
  printf("HWE Result = %c\n", ret_hwe);

  status = ecall_ld(compute_enclave_id, &ret_status, ld_para_1, ld_para_2, &ret_ld, 1);
  if(status != SGX_SUCCESS || ret_status != 0) {
      printf("failed to calculate LD.\n");
      return false;
  } 
  printf("LD Result = %c\n", ret_ld);

  status = ecall_catt(compute_enclave_id, &ret_status, catt_para, &ret_catt, 1);
  if(status != SGX_SUCCESS || ret_status != 0) {
      printf("failed to calculate CATT.\n");
      return false;
  } 
  printf("CATT Result = %c\n", ret_catt);

  status = ecall_fet(compute_enclave_id, &ret_status, fet_para, &ret_fet, 1);
  if(status != SGX_SUCCESS || ret_status != 0) {
      printf("failed to calculate FET.\n");
      return false;
  } 
  printf("FET Result = %c\n", ret_fet);

  Json resultJson = Json::object{
      {"LD", ret_ld - '0' },
      {"HWE", ret_hwe - '0'},
      {"CATT", ret_catt - '0'},
      {"FET", ret_fet - '0'}
  };
  std::string resultStr = resultJson.dump();
  resultSize = resultStr.size();
  *result = (uint8_t*)malloc(resultSize);
  memcpy(*result, resultStr.c_str(), resultSize);
  return true;
}