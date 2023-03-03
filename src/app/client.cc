#include <iostream>

#include "CryptoPrimitive.h"
#include "FileSender.h"
#include "OrderSender.h"
#include "SSLConnection.h"
#include "json11.h"

void Usage() {
  std::cout << "operation:u/c/q"<<std::endl;
  std::cout << "u:upload data"<<std::endl;
  std::cout << "c:process data"<<std::endl;
  std::cout << "q:quit"<<std::endl;
}

using namespace json11;

int main()
{
  auto sslConnection = std::make_shared<SSLConnection>("127.0.0.1", 1666, kCLIENTSIDE);
  if(!sslConnection->ConnectSSL()) {
    fprintf(stderr, "client:ssl connection failed.\n");
    exit(EXIT_FAILURE);
  }

  Usage();
  char order;
  OrderSender orderSender(sslConnection);
  FileSender fileSender(sslConnection);
  bool run = true;
  while(run) {
    std::cout << "please input the operation:";
    std::cin>>order;
    switch(order){
      case 'u':{
        std::string filePath;
        std::cout << "please input file path:";
        std::cin >> filePath;
        if(!orderSender.SendOrder(kUPLOAD)){
          fprintf(stderr, "client:cannot send uploading order.\n");
          run = false;
          continue;
        }
        if(fileSender.SendFile(filePath)) {
          std::cout << "client:successfully upload file:" << filePath << std::endl;
        } else {
          std::cout << "client:failed to upload file" << std::endl;
          run = false;
        }
        break;
      }
      case 'c':{
        if(!orderSender.SendOrder(kPROCESS)){
          fprintf(stderr, "client:cannot send processing order.\n");
          run = false;
          continue;
        }
        int ld_para_1, ld_para_2, hwe_para, catt_para, fet_para;
        std::cout << "please input LD parameters(para1 para2):";
        std::cin >> ld_para_1 >> ld_para_2;
        std::cout << "please input HWE parameter(para1):";
        std::cin >> hwe_para;
        std::cout << "please input CATT parameter(para1):";
        std::cin >> catt_para;
        std::cout << "please input FET parameter(para1):";
        std::cin >> fet_para;
        Json paras = Json::object {
            {"LD", Json::array{ld_para_1, ld_para_2}},
            {"HWE", hwe_para},
            {"CATT", catt_para},
            {"FET", fet_para}
        };

        std::string paraStr = paras.dump();
        if(!orderSender.SendOperation(kGWASRequest, (uint8_t*)paraStr.c_str(), paraStr.size())) {
          fprintf(stderr, "client:cannot send operation.\n");
          run = false;
          continue;
        }

        OperationType resultType;
        uint8_t* result;
        uint32_t resultSize;
        if(!orderSender.ReceiveResult(resultType, &result, resultSize)) {
          fprintf(stderr, "client:cannot receive result.\n");
          run = false;
        }

        std::string err;
        Json resultJson = Json::parse(std::string((char*)result, resultSize), err);
        std::cout << "LD:" << resultJson["LD"].int_value() << std::endl;
        std::cout << "HWE:" << resultJson["HWE"].int_value() << std::endl;
        std::cout << "CATT:" << resultJson["CATT"].int_value() << std::endl;
        std::cout << "FET:" << resultJson["FET"].int_value() << std::endl;
        free(result);
        break;
      }
      case 'q': {
        if(!orderSender.SendOrder(kQUIT)){
          fprintf(stderr, "client:cannot send quit order.\n");
        }
        run = false;
        break;
      }
      default: {
        std::cout << "operation error" << std::endl;
        Usage();
        break;
      }
    }
  }
  sslConnection->Finish();
  return 0;
}
