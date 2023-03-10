// compress original dataset
// remove duplicate record
// output total rs ids in a seperate file

#include <cstring>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#define MAX_LINE 50000

typedef struct SNP {
  uint32_t rs_id_int;
  uint32_t counters[4];
  uint8_t data[273];
} SNP;

int main(int argc, char** argv) {
  FILE* infile = fopen(argv[1], "r");
  std::set<uint32_t> existedID;

  char line[MAX_LINE];
  std::string dataDir = "../data/client_";
  std::string suffix = ".gwas";
  int file_count = 0;
  std::ofstream ofs, idList;

  idList.open("../data/idList.txt", std::ios::out);

  int index = 0;
  uint8_t x = 0;
  SNP snp;
  char rs_id[16];
  char* dummy;
  unsigned long temp = 0;
  int line_count = 0;
  bool rs_flag = false;
  
  while (fgets(line, MAX_LINE, infile)) {
    /* Ignore comment lines */
    if (line[0] == '#') {
      continue;
    }
    memset(&snp, 0, sizeof(SNP));
    memset(rs_id, 0, sizeof(rs_id));
    index = 0;
    rs_flag = false;

    char* token;
    uint32_t writeBytes = 0;

    token = strtok(line, "\t");
    while (token != NULL) {
      if (token[0] == 'r' && token[1] == 's') {
        strncpy(rs_id, token + 2, sizeof(rs_id));
        temp = strtoul(rs_id, &dummy, 10);
        snp.rs_id_int = (uint32_t)temp;
        if (existedID.find(temp) == existedID.end()) {
          rs_flag = true;
          ++line_count;
          auto s = std::to_string(temp) + '\n';
          idList.write(s.c_str(), s.size());
          existedID.insert(temp);
        }
      } else if (token[1] == '|') {
        x = (token[0] - '0') * 2 + (token[2] - '0');
        ++snp.counters[x];
        snp.data[index / 4] =
            snp.data[index / 4] | (x << ((3 - index % 4) * 2));
        ++index;
      }
      token = strtok(NULL, "\t");
    }
    // write one snp
    if (rs_flag) {
      if (!ofs.is_open()) {
        ++file_count;
        std::string filePath = dataDir + std::to_string(file_count) + suffix;
        ofs.open(filePath.c_str(), std::ios::out);
      }
      ofs.write((char*)&snp, sizeof(SNP));
      if (line_count % 50000 == 0) {
        ofs.close();
      }
    }
  }
  printf("number of lines = %d\n", line_count);
  ofs.close();
  idList.close();   
  return 0;
}