#ifndef FROG_INCLUDE_GWASEXECUTOR_H_
#define FROG_INCLUDE_GWASEXECUTOR_H_
#include <stdint.h>

class GWASExecutor {
 public:
  GWASExecutor(uint8_t* paras, uint32_t parasLen);
  ~GWASExecutor();
  bool execute(uint8_t** result, uint32_t& resultSize);
 private:
  uint32_t ld_para_1, ld_para_2;
  uint32_t hwe_para, catt_para, fet_para;
};

#endif  // FROG_INCLUDE_GWASEXECUTOR_H_
