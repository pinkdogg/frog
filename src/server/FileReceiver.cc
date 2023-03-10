#include "FileReceiver.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include "EnclaveCompute_u.h"
#include "EnclaveBudget_u.h"

extern sgx_enclave_id_t budget_enclave_id, compute_enclave_id;

FileReceiver::FileReceiver(std::shared_ptr<SSLConnection> sslConnection)
  :sslConnection_(sslConnection){

}

bool FileReceiver::ReceiveFile() {
  std::cout << "FileReceiver:start receiving file." << std::endl;
  //receive fileName hash
  DataMsg_t* msgBuffer;
  std::string strFileNameHash;
  uint32_t receivedSize;
  sslConnection_->ReceiveData((uint8_t**)&msgBuffer, receivedSize);

  if(msgBuffer->header.dataMsgType != kFileMetaData) {
    //todo 
    //terminate and send error message
    fprintf(stderr, "FileReceiver: receive file fail.\n");
  }
  FileMetaData* metaData = (FileMetaData*)msgBuffer->data;

  std::stringstream ss;
  for(int i = 0; i < 32; i++) {
    ss << std::setfill('0') << std::setw(2) <<std::hex << (unsigned int)metaData->hash[i];
  }
  strFileNameHash = ss.str();

  // send encrypted privacy_budget to enclave_budget
  // send encrypted encryption_key to enclave_compute
  ecall_add_privacy_budget(budget_enclave_id, strFileNameHash.c_str(), metaData->encrypted_privacy_budget);
  ecall_add_encryption_key(compute_enclave_id, strFileNameHash.c_str(), metaData->encrypted_file_encryption_key);

  free(msgBuffer);
  std::fstream fileStream;
  fileStream.open("./data/gwas/" + strFileNameHash, std::ios::out);
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
    ecall_decrypt_process(compute_enclave_id, strFileNameHash.c_str(), msgBuffer->data, receivedSize - sizeof(DataMsg_t));
    free(msgBuffer);
  }
  return true;
}

FileReceiver::~FileReceiver() {

}