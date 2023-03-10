#ifndef FROG_INCLUDE_DEFINE_H_
#define FROG_INCLUDE_DEFINE_H_

enum HashSet {
  kSHA256 = 0,
  kMD5 = 1,
  kSHA1 = 2
};

enum EncryptSet {
  kAES_256_GCM = 0, 
  kAES_128_GCM = 1, 
  kAES_256_CFB = 2, 
  kAES_128_CFB = 3
};

const uint32_t kCRYPTO_BLOCK_SIZE = 16;
const uint8_t kAES_256_GCM_KEY[32] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

typedef struct {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[273];
}SNP;

const uint32_t kREADSIZE = sizeof(SNP) * (16 << 10);
enum OrderType {
  kUPLOAD = 0,
  kPROCESS = 1,
  kQUIT =2,
};

enum OperationType {
  kGWASRequest = 0,
  kGWASResponse = 1,
};

enum DataMsgType {
  kFileMetaData = 0,
  kFileBody,
  kFileEnd,
  kClientError,
  kServerError
};

enum SSLConnectionType {
  kCLIENTSIDE = 0, kSERVERSIDE = 1
};

typedef struct {
  unsigned char hash[32];
  uint32_t encrypted_privacy_budget;
  uint8_t encrypted_file_encryption_key[32];
} FileMetaData;

typedef struct {
  union {
    OrderType orderType;
    OperationType operationType;
  };
  uint8_t data[];
} OrderMsg_t;

typedef struct {
  DataMsgType dataMsgType;
}DataMsgHeader_t;

typedef struct {
  DataMsgHeader_t header;
  uint8_t data[];
}DataMsg_t;

const char kCaCrt[] = "../key/ca/ca.crt";
const char kClientCrt[] = "../key/client/client.crt";
const char kClientKey[] = "../key/client/client.key";
const char kServerCrt[] = "../key/server/server.crt";
const char kServerKey[] = "../key/server/server.key";

#endif//FROG_INCLUDE_DEFINE_H_
