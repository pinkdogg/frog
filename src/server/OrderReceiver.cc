#include "OrderReceiver.h"
#include <cstring>

OrderReceiver::OrderReceiver(std::shared_ptr<SSLConnection> sslConnection)
  :sslConnection_(sslConnection){

}

bool OrderReceiver::ReceiveOrder(OrderType& orderType) {
  OrderMsg_t* orderMsg;
  uint32_t receivedSize;
  if(!sslConnection_->ReceiveData((uint8_t**)&orderMsg, receivedSize)) {
      fprintf(stderr, "OrderReceiver:receive operation failed.\n");
      return false;
  }
  orderType = orderMsg->orderType;
  free(orderMsg);
  return true;
}

bool OrderReceiver::ReceiveOperation(OperationType& operationType, uint8_t** paras, uint32_t& parasLen) {
  OrderMsg_t* orderMsg;
  uint32_t receivedSize;
  if(!sslConnection_->ReceiveData((uint8_t**)&orderMsg, receivedSize)) {
    fprintf(stderr, "OrderReceiver:receive operation failed.\n");
    return false;
  }
  operationType = orderMsg->operationType;
  *paras = (uint8_t*)malloc(receivedSize - sizeof(OrderMsg_t));
  memcpy(*paras, orderMsg->data, receivedSize - sizeof(OrderMsg_t));
  parasLen = receivedSize - sizeof(OrderMsg_t);
  free(orderMsg);
  return true;
}

bool OrderReceiver::SendResult(OperationType resultType, uint8_t* result, const uint32_t& resultSize) {
  OrderMsg_t* orderMsg = (OrderMsg_t*)malloc(sizeof(OrderMsg_t) + resultSize);
  orderMsg->operationType = resultType;
  memcpy(orderMsg->data, result, resultSize);
  if(!sslConnection_->SendData((uint8_t*)orderMsg, sizeof(OrderMsg_t)+resultSize)) {
    fprintf(stderr, "OrderSender:send result message failed.\n");
    return false;
  }
  free(orderMsg);
  return true;
}
OrderReceiver::~OrderReceiver() {

}