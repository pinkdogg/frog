#include <iostream>

#include "CryptoPrimitive.h"
#include "FileSender.h"
#include "OrderSender.h"
#include "SSLConnection.h"
#include "json11.h"
#include "argparse.hpp"

void Usage() {
  std::cout << "operation:u/p"<<std::endl;
  std::cout << "u:upload data"<<std::endl;
  std::cout << "p:process data"<<std::endl;
}

using namespace json11;

void initArgumentParser(argparse::ArgumentParser& program) {
  program.add_argument("-o", "--operation")
  .help("specifies operations to be done")
  .required();

  program.add_argument("-f", "--file")
  .help("path of file to be uploaded");

  program.add_argument("-p", "--privacy_budget")
  .scan<'u', uint32_t>()
  .help("privacy budget of this file");

  program.add_argument("-k", "--key")
  .help("encryption key of file");

  program.add_argument("--LD")
  .help("LD")
  .nargs(2)
  .scan<'i', int>();

  program.add_argument("--HWE")
  .help("HWE")
  .scan<'i', int>();

  program.add_argument("--CATT")
  .help("CATT")
  .scan<'i', int>();

  program.add_argument("--FET")
  .help("FET")
  .scan<'i', int>();
}

int main(int argc, char* argv[])
{
  // parse arguments
  argparse::ArgumentParser program("client", "1.0");
  initArgumentParser(program);
  try {
    program.parse_args(argc, argv);
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  std::string order;
  order = program.get<std::string>("--operation");

  auto sslConnection = std::make_shared<SSLConnection>("127.0.0.1", 1666, kCLIENTSIDE);
  if(!sslConnection->ConnectSSL()) {
    fprintf(stderr, "client:ssl connection failed.\n");
    exit(EXIT_FAILURE);
  }

  OrderSender orderSender(sslConnection);
  FileSender fileSender(sslConnection);

  switch(order[0]){
    case 'u':{
      if(!orderSender.SendOrder(kUPLOAD)){
        fprintf(stderr, "client:cannot send processing order.\n");
      }
      std::string filePath = program.get<std::string>("--file");
      uint32_t privacy_budget = program.get<uint32_t>("--privacy_budget");
      
      if(fileSender.SendFile(filePath, privacy_budget, kAES_256_GCM_KEY)) {
        std::cout << "client:successfully upload file:" << filePath << std::endl;
      } else {
        std::cout << "client:failed to upload file" << std::endl;
      }
      break;
    }
    case 'p':{
      if(!orderSender.SendOrder(kPROCESS)){
        fprintf(stderr, "client:cannot send processing order.\n");
      }
      auto LD_params = program.get<std::vector<int>>("--LD");
      auto HWE_param = program.get<int>("--HWE");
      auto FET_param = program.get<int>("--FET");
      auto CATT_param = program.get<int>("--CATT");
      Json paras = Json::object {
          {"LD", Json::array{LD_params[0], LD_params[1]}},
          {"HWE", HWE_param},
          {"CATT", CATT_param},
          {"FET", FET_param}
      };

      std::string paraStr = paras.dump();
      if(!orderSender.SendOperation(kGWASRequest, (uint8_t*)paraStr.c_str(), paraStr.size())) {
        fprintf(stderr, "client:cannot send operation.\n");
      }

      OperationType resultType;
      uint8_t* result;
      uint32_t resultSize;
      if(!orderSender.ReceiveResult(resultType, &result, resultSize)) {
        fprintf(stderr, "client:cannot receive result.\n");
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
    default: {
      std::cout << "operation error" << std::endl;
      Usage();
      break;
    }
  }
  if(!orderSender.SendOrder(kQUIT)){
    fprintf(stderr, "client:cannot send quit order.\n");
  }
  sslConnection->Finish();
  return 0;
}
