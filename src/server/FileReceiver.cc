#include "FileReceiver.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>

FileReceiver::FileReceiver(std::shared_ptr<SSLConnection> sslConnection)
  :sslConnection_(sslConnection){

}

bool FileReceiver::ReceiveFile() {
  std::cout << "FileReceiver:start receiving file." << std::endl;
  //receive fileName hash
  DataMsg_t* msgBuffer;
  unsigned char fileNameHash[32];
  uint32_t receivedSize;
  sslConnection_->ReceiveData((uint8_t**)&msgBuffer, receivedSize);
  if(msgBuffer->header.dataMsgType != kFileNameHash) {
    //todo terminate and send error message
  }
  memcpy(fileNameHash, msgBuffer->data, 32);
  free(msgBuffer);
  std::fstream fileStream;
  std::stringstream ss;
  for(int i = 0; i < 32; i++) {
    ss << std::setfill('0') << std::setw(2) <<std::hex << (unsigned int)fileNameHash[i];
  }
  fileStream.open("./data/gwas/" + ss.str(), std::ios::out);
  if(!fileStream.is_open()) {
    //todo terminate and send error message
  }
  while(true) {
    sslConnection_->ReceiveData((uint8_t**)&msgBuffer, receivedSize);
    if(msgBuffer->header.dataMsgType == kFileEnd) {
      fileStream.close();
      break;
    }
    fileStream.write((char*)msgBuffer->data, receivedSize - sizeof(DataMsg_t));
    free(msgBuffer);
  }
  return true;
}

FileReceiver::~FileReceiver() {

}