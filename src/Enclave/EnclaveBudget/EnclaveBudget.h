#ifndef _ENCLAVEBUDGET_H_
#define _ENCLAVEBUDGET_H_

int printf(const char* fmt, ...);
uint32_t message_exchange(uint8_t* secret_data, size_t secret_data_size);

#endif