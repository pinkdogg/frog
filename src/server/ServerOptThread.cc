#include "ServerOptThread.h"
#include <boost/thread/thread.hpp>
#include <iostream>
#include <thread>
#include <GWASExecutor.h>

ServerOptThread::ServerOptThread(std::shared_ptr<SSLConnection> sslConnection)
  :sslConnection_(sslConnection), fileReceiver_(sslConnection),
      orderReceiver_(sslConnection){

}

ServerOptThread::~ServerOptThread() {
  std::cout << "ServerOptThread is deconstructing." << std::endl;
  printf("=========================================\n");
}

void ServerOptThread::Run() {
  bool run = true;
  while(run) {
    OrderType orderType;
    if(!orderReceiver_.ReceiveOrder(orderType)) {
      fprintf(stderr, "ServerOptThread:receive order error.\n");
      run = false;
      continue;
    }
    switch(orderType) {
      case kUPLOAD:{
        if(!fileReceiver_.ReceiveFile()) {
          fprintf(stderr, "ServerOptThread:receive file error.\n");
          run = false;
        }
        break;
      }
      case kPROCESS:{
        printf("ServerOptThread:start processing file.\n");
        OperationType operationType;
        uint8_t* paras;
        uint32_t parasLen;
        if(!orderReceiver_.ReceiveOperation(operationType, &paras, parasLen)) {
          fprintf(stderr, "ServerOptThread:cannot receive operation.\n");
          run = false;
          free(paras);
          continue;
        }
        switch(operationType) {
          case kGWASRequest:{
            GWASExecutor gwasExecutor(paras, parasLen);
            uint8_t* result;
            uint32_t resultSize;
            
            gwasExecutor.execute(&result, resultSize);

            if(!orderReceiver_.SendResult(kGWASResponse, result, resultSize)) {
              fprintf(stderr, "client:cannot send result.\n");
              run = false;
            }
            free(result);
            break;
          }
          default:{
            break;
          }
        }
        free(paras);
        break;
      }
      case kQUIT:{
        printf("ServerOptThread:quit.\n");
        run = false;
        break;
      }
    }
  }
  sslConnection_->Finish();
}