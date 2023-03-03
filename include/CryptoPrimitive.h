#ifndef FROG_INCLUDE_CRYPTOPRIMITIVE_H_
#define FROG_INCLUDE_CRYPTOPRIMITIVE_H_

#include <openssl/evp.h>
#include <stdint.h>
#include <cstring>
#include "define.h"

const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

class CryptoPrimitive {
 public:
  CryptoPrimitive(HashSet hashType, EncryptSet cipherType) 
    :hashType_(hashType),cipherType_(cipherType) {
      iv_ = (uint8_t*) malloc(kCRYPTO_BLOCK_SIZE);
      if (!iv_) {
          fprintf(stderr, "CryptoTool: allocate the memory for iv fail.\n");
          exit(EXIT_FAILURE);
      }
      memset(iv_, 0, kCRYPTO_BLOCK_SIZE);
      cipherCTX_ = EVP_CIPHER_CTX_new();
    }
  void GenerateHash(const uint8_t* data, size_t dataSize, unsigned char* hash,
                    unsigned int* hashSize);
  void EncryptWithKey(uint8_t* plaintext, const uint32_t dataSize, uint8_t* ciphertext, const uint8_t* key);
  void DecryptWithKey(uint8_t* ciphertext, const uint32_t dataSize, uint8_t* plaintext, const uint8_t* key);
  
 private:
  // type of hash
  HashSet hashType_;
  EncryptSet cipherType_;
  uint8_t* iv_;
  EVP_CIPHER_CTX* cipherCTX_;
};
#endif  // FROG_INCLUDE_CRYPTOPRIMITIVE_H_
