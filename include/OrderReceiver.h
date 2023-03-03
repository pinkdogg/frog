#ifndef FROG_INCLUDE_ORDERRECEIVER_H_
#define FROG_INCLUDE_ORDERRECEIVER_H_

#include "SSLConnection.h"

class OrderReceiver {
 public:
  OrderReceiver(std::shared_ptr<SSLConnection> sslConnection);
  ~OrderReceiver();
  bool ReceiveOrder(OrderType& orderType);
  bool ReceiveOperation(OperationType& operationType, uint8_t** paras, uint32_t& parasLen);
  bool SendResult(OperationType resultType, uint8_t* result, const uint32_t& resultSize);
 private:
  std::shared_ptr<SSLConnection> sslConnection_;
};
#endif  // FROG_INCLUDE_ORDERRECEIVER_H_
