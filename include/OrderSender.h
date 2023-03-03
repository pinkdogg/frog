#ifndef FROG_INCLUDE_ORDERSENDER_H_
#define FROG_INCLUDE_ORDERSENDER_H_
#include "SSLConnection.h"

class OrderSender {
 public:
  explicit OrderSender(std::shared_ptr<SSLConnection> sslConnection);
  ~OrderSender();
  bool SendOrder(OrderType orderType);
  bool SendOperation(OperationType operationType, uint8_t* paras, uint32_t parasLen);
  bool ReceiveResult(OperationType& resultType, uint8_t** result, uint32_t& resultSize);
 private:
  std::shared_ptr<SSLConnection> sslConnection_;
};
#endif  // FROG_INCLUDE_ORDERSENDER_H_
