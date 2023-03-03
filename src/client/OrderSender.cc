#include "OrderSender.h"
#include <cstring>

OrderSender::OrderSender(std::shared_ptr<SSLConnection> sslConnection)
  :sslConnection_(sslConnection) {

}

bool OrderSender::SendOrder(OrderType orderType) {
  OrderMsg_t orderMsg;
  orderMsg.orderType = orderType;
  if(!sslConnection_->SendData((uint8_t*)&orderMsg, sizeof(OrderMsg_t))) {
    fprintf(stderr, "OrderSender:failed to send order.\n");
    return false;
  }
  return true;
}

bool OrderSender::SendOperation(OperationType operationType, uint8_t* paras, uint32_t parasLen) {
  OrderMsg_t* orderMsg = (OrderMsg_t*)malloc(sizeof(OrderMsg_t) + parasLen);
  orderMsg->operationType = operationType;
  memcpy(orderMsg->data, paras, parasLen);
  if(!sslConnection_->SendData((uint8_t*)orderMsg, sizeof(OrderMsg_t)+parasLen)) {
    fprintf(stderr, "OrderSender:send operation message failed.\n");
    return false;
  }
  free(orderMsg);
  return true;
}

bool OrderSender::ReceiveResult(OperationType& resultType, uint8_t** result, uint32_t& resultSize) {
  OrderMsg_t* orderMsg;
  uint32_t receivedSize;
  if(!sslConnection_->ReceiveData((uint8_t**)&orderMsg, receivedSize)) {
    fprintf(stderr, "OrderReceiver:receive operation failed.\n");
    return false;
  }
  resultType = orderMsg->operationType;
  *result = (uint8_t*)malloc(receivedSize - sizeof(OrderMsg_t));
  memcpy(*result, orderMsg->data, receivedSize - sizeof(OrderMsg_t));
  resultSize = receivedSize - sizeof(OrderMsg_t);
  free(orderMsg);
  return true;
}

OrderSender::~OrderSender() {

}