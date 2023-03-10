#include "FileSender.h"
#include <iostream>
#include <fstream>
#include <cstring>

FileSender::FileSender(std::shared_ptr<SSLConnection> sslConnection)
  : sslConnection_(sslConnection), cryptoPrimitive_(kSHA256, kAES_256_GCM){

}

FileSender::~FileSender() {

}

bool FileSender::SendFile(const std::string& filePath, uint32_t privacy_budget, const uint8_t encryption_key[32]) {
  std::cout << "client:start uploading file:" << filePath << std::endl;
  DataMsg_t* msgBuffer;
  std::fstream fileStream;
  std::string fileName = getFileName(filePath);
  fileStream.open(filePath, std::ios::in);
  if(!fileStream.is_open()) {
    fprintf(stderr, "FileSender:cannot open file %s.\n", fileName.c_str());
    //todo
    // send error message to server, so that server can terminate the connection normally
    return false;
  }

  //todo
  // enclave_budget mk, vk encrypt privacy_budget
  // enclave_compute mk, vk encrypt encryption key
  
  // send fileName hash, privacy_budget, encryption key
  msgBuffer = (DataMsg_t*)malloc(sizeof(DataMsg_t)+sizeof(FileMetaData));
  FileMetaData* metaData = (FileMetaData*)msgBuffer->data;
  unsigned int hashSize;
  cryptoPrimitive_.GenerateHash((uint8_t*)fileName.c_str(), fileName.size(), metaData->hash, &hashSize);
  memcpy(&metaData->encrypted_privacy_budget, &privacy_budget, sizeof(metaData->encrypted_privacy_budget));
  memcpy(&metaData->encrypted_file_encryption_key, encryption_key, sizeof(metaData->encrypted_file_encryption_key));
  msgBuffer->header.dataMsgType = kFileMetaData;
  sslConnection_->SendData((uint8_t*)msgBuffer, sizeof(DataMsg_t)+sizeof(FileMetaData));

  free(msgBuffer);

  // send file body
  uint8_t* readBuffer = (uint8_t*)malloc(kREADSIZE);
  msgBuffer = (DataMsg_t*)malloc(sizeof(DataMsg_t) + kREADSIZE);
  uint32_t len;
  while(true) {
    fileStream.read((char*)readBuffer, kREADSIZE);
    len = fileStream.gcount();
    if(len > 0) {
      msgBuffer->header.dataMsgType = kFileBody;
      cryptoPrimitive_.EncryptWithKey(readBuffer, len, msgBuffer->data, encryption_key);
      sslConnection_->SendData((uint8_t*)msgBuffer, sizeof(DataMsg_t)+len);
    } else {
      break;
    }
  }
  msgBuffer->header.dataMsgType = kFileEnd;
  sslConnection_->SendData((uint8_t*)msgBuffer, sizeof(DataMsg_t));
  free(msgBuffer);
  fileStream.close();
  return true;
}

std::string FileSender::getFileName(const std::string& filePath) {
  std::string fileName = filePath;
  int i;
  for(i = filePath.size(); i >= 0; --i) {
    if(filePath[i] == '/') {
      break;
    }
  }
  if(i >= 0) {
    fileName = filePath.substr(i+1);
  }
  return fileName;
}