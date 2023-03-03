#ifndef FROG_INCLUDE_FILERECEIVER_H_
#define FROG_INCLUDE_FILERECEIVER_H_

#include "SSLConnection.h"
#include "CryptoPrimitive.h"

class FileReceiver {
 public:
  FileReceiver(std::shared_ptr<SSLConnection> sslConnection);
  ~FileReceiver();
  bool ReceiveFile();
 private:
  std::shared_ptr<SSLConnection> sslConnection_;
};
#endif//FROG_INCLUDE_FILERECEIVER_H_
