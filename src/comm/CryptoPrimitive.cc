#include "CryptoPrimitive.h"

void CryptoPrimitive::GenerateHash(const uint8_t *data, size_t dataSize, unsigned char*hash,
								   unsigned int *hashSize) {
  switch (hashType_) {
	case kSHA1:
	  if(!EVP_Digest(data, dataSize, hash, hashSize, EVP_sha1(), nullptr)) {
		fprintf(stderr, "CryptoPrimitie: hash error.\n");
		exit(EXIT_FAILURE);
	  }
	  break;
	case kSHA256:
	  if(!EVP_Digest(data, dataSize, hash, hashSize, EVP_sha256(), nullptr)) {
		fprintf(stderr, "CryptoPrimitie: hash error.\n");
		exit(EXIT_FAILURE);
	  }
	  break;
	case kMD5:
	  if(!EVP_Digest(data, dataSize, hash, hashSize, EVP_md5(), nullptr)) {
		fprintf(stderr, "CryptoPrimitie: hash error.\n");
		exit(EXIT_FAILURE);
	  }
	  break;
  }
}

void CryptoPrimitive::EncryptWithKey(uint8_t* plaintext, const uint32_t dataSize, uint8_t* ciphertext, const uint8_t* key) {
    int cipherLen = 0;
    int len = 0;

    switch (cipherType_) {
        case kAES_128_CFB: 
            if (!EVP_EncryptInit_ex(cipherCTX_, EVP_aes_128_cfb(), NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case kAES_256_CFB:
            if (!EVP_EncryptInit_ex(cipherCTX_, EVP_aes_256_cfb(), NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case kAES_256_GCM:
            EVP_EncryptInit_ex(cipherCTX_, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(cipherCTX_, EVP_CTRL_AEAD_SET_IVLEN, kCRYPTO_BLOCK_SIZE, NULL);
            if (!EVP_EncryptInit_ex(cipherCTX_, NULL, NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            EVP_EncryptUpdate(cipherCTX_, NULL, &cipherLen, gcm_aad, sizeof(gcm_aad));
            break;
        case kAES_128_GCM:
            EVP_EncryptInit_ex(cipherCTX_, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(cipherCTX_, EVP_CTRL_AEAD_SET_IVLEN, kCRYPTO_BLOCK_SIZE, NULL);
            if (!EVP_EncryptInit_ex(cipherCTX_, NULL, NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            EVP_EncryptUpdate(cipherCTX_, NULL, &cipherLen, gcm_aad, sizeof(gcm_aad));
            break;
    }

    // encrypt the plaintext
    if (!EVP_EncryptUpdate(cipherCTX_, ciphertext, &cipherLen, plaintext, 
        dataSize)) {
        fprintf(stderr, "CryptoTool: Encryption error.\n");
        exit(EXIT_FAILURE);
    }
    EVP_EncryptFinal_ex(cipherCTX_, ciphertext + cipherLen, &len);
    cipherLen += len;
	
    if (cipherLen != dataSize) {
        fprintf(stderr, "CryptoTool: encryption output size not equal to origin size.\n");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_reset(cipherCTX_);
}

void CryptoPrimitive::DecryptWithKey(uint8_t* ciphertext, const uint32_t dataSize, uint8_t* plaintext, const uint8_t* key) {
	int plainLen;
    int len;
    switch (cipherType_) {
        case kAES_128_CFB:
            if (!EVP_DecryptInit_ex(cipherCTX_, EVP_aes_128_cfb(), NULL, 
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case kAES_256_CFB:
            if (!EVP_DecryptInit_ex(cipherCTX_, EVP_aes_256_cfb(), NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case kAES_128_GCM:
            EVP_DecryptInit_ex(cipherCTX_, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(cipherCTX_, EVP_CTRL_AEAD_SET_IVLEN, kCRYPTO_BLOCK_SIZE, NULL);
            if (!EVP_DecryptInit_ex(cipherCTX_, NULL, NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            EVP_DecryptUpdate(cipherCTX_, NULL, &plainLen, gcm_aad, sizeof(gcm_aad));
            break;
        case kAES_256_GCM:
            EVP_DecryptInit_ex(cipherCTX_, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(cipherCTX_, EVP_CTRL_AEAD_SET_IVLEN, kCRYPTO_BLOCK_SIZE, NULL);
            if (!EVP_DecryptInit_ex(cipherCTX_, NULL, NULL,
                key, iv_)) {
                fprintf(stderr, "CryptoTool: Init error.\n");
                exit(EXIT_FAILURE);
            }
            EVP_DecryptUpdate(cipherCTX_, NULL, &plainLen, gcm_aad, sizeof(gcm_aad));
            break;
    }

    // decrypt the plaintext
    if (!EVP_DecryptUpdate(cipherCTX_, plaintext, &plainLen, ciphertext, 
        dataSize)) {
        fprintf(stderr, "CryptoTool: Decrypt error.\n");
        exit(EXIT_FAILURE);
    }

    EVP_DecryptFinal_ex(cipherCTX_, plaintext + plainLen, &len);
    
    plainLen += len;

    if (plainLen != dataSize) {
        fprintf(stderr, "CryptoTool: Decrypt output size not equal to origin size.\n");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_reset(cipherCTX_);
}

