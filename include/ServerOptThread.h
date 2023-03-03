#ifndef FROG_INCLUDE_SERVEROPTTHREAD_H_
#define FROG_INCLUDE_SERVEROPTTHREAD_H_
#include "FileReceiver.h"
#include "OrderReceiver.h"
#include "SSLConnection.h"

class ServerOptThread {
 public:
  ServerOptThread(std::shared_ptr<SSLConnection> sslConnection);
  ~ServerOptThread();
  void Run();
 private:
  std::shared_ptr<SSLConnection> sslConnection_;
  OrderReceiver orderReceiver_;
  FileReceiver fileReceiver_;
};
#endif  // FROG_INCLUDE_SERVEROPTTHREAD_H_
