#ifndef FROG_INCLUDE_SERVER_H_
#define FROG_INCLUDE_SERVER_H_
#include <iostream>
#include <fstream>
#include "sgx_urts.h"

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
        // std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
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

void ComputeUnSealData(sgx_enclave_id_t enclave_id, char* filename) {
  // Read the sealed blob from the file
  size_t fsize = get_file_size(filename);
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if(read_file_to_buf(filename, temp_buf, fsize)) {
    // Unseal the sealed blob
    sgx_status_t retval;
    sgx_status_t ret = ecall_compute_unseal_data(enclave_id, &retval, temp_buf, fsize);
  }
  free(temp_buf);
}

void BudgetUnSealData(sgx_enclave_id_t enclave_id, char* filename) {
  // Read the sealed blob from the file
  size_t fsize = get_file_size(filename);
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if(read_file_to_buf(filename, temp_buf, fsize)) {
    // Unseal the sealed blob
    sgx_status_t retval;
    sgx_status_t ret = ecall_budget_unseal_data(enclave_id, &retval, temp_buf, fsize);
  }
  free(temp_buf);
}
#endif