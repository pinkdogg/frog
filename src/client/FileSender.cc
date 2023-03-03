#include "FileSender.h"
#include <iostream>
#include <fstream>
#include <cstring>

FileSender::FileSender(std::shared_ptr<SSLConnection> sslConnection)
  : sslConnection_(sslConnection), cryptoPrimitive_(kSHA256, kAES_256_GCM){

}

FileSender::~FileSender() {

}

bool FileSender::SendFile(const std::string& filePath) {
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
  // send fileName hash
  unsigned char hash[32];
  unsigned int hashSize;
  cryptoPrimitive_.GenerateHash((uint8_t*)fileName.c_str(), fileName.size(), hash, &hashSize);
  msgBuffer = (DataMsg_t*)malloc(sizeof(DataMsg_t)+hashSize);
  msgBuffer->header.dataMsgType = kFileNameHash;
  memcpy(msgBuffer->data, hash, hashSize);
  sslConnection_->SendData((uint8_t*)msgBuffer, sizeof(DataMsg_t)+hashSize);
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
      cryptoPrimitive_.EncryptWithKey(readBuffer, len, msgBuffer->data, kAES_256_GCM_KEY);
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