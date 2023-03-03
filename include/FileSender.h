#ifndef FROG_INCLUDE_FILESENDER_H_
#define FROG_INCLUDE_FILESENDER_H_

#include "SSLConnection.h"
#include "CryptoPrimitive.h"

class FileSender {
 public:
  explicit FileSender(std::shared_ptr<SSLConnection> sslConnection);
  bool SendFile(const std::string& filePath);
  ~FileSender();
 private:
  std::string getFileName(const std::string& filePath);
 private:
  std::shared_ptr<SSLConnection> sslConnection_;
  CryptoPrimitive cryptoPrimitive_;
};
#endif//FROG_INCLUDE_FILESENDER_H_
