#ifndef _ENCLAVEBUDGET_H_
#define _ENCLAVEBUDGET_H_
#include <stdio.h>
#include <stdarg.h>
#include <map>

#define UNUSED(val) (void)(val)

#define RESPONDER_PRODID 1

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

dh_session_t g_session;

// This is hardcoded responder enclave's MRSIGNER for demonstration purpose. The content aligns to responder enclave's signing key
sgx_measurement_t g_responder_mrsigner = {
	{
		0x6c, 0x44, 0x40, 0x99, 0xd3, 0x47, 0x84, 0xc9, 0x41, 0x52, 0x65, 0x20, 0xbc, 0xad, 0x93, 0xb2, 
        0x58, 0x9c, 0x92, 0x4f, 0x9b, 0xdf, 0xa7, 0x7b, 0xcb, 0xeb, 0x3b, 0xaa, 0xfe, 0x14, 0x92, 0xf8
	}
};

// secret key
const size_t aes_128bit_key_len = 16;
uint8_t aes_128bit_key[aes_128bit_key_len] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};


int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    print_string_ocall(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

uint32_t message_exchange(uint8_t* secret_data, size_t secret_data_size);
#endif