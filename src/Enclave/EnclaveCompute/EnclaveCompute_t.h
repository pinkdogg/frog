#ifndef ENCLAVECOMPUTE_T_H__
#define ENCLAVECOMPUTE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "datatypes.h"
#include "dh_session_protocol.h"
#include "sgx_cpuid.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t session_request(sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t generate_response(secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, uint32_t session_id);
uint32_t end_session(uint32_t session_id);
void ecall_decrypt_process(const char* strFileNameHash, uint8_t* ciphertext, uint32_t len_data);
uint32_t ecall_hwe(uint32_t rs_id, int* hweResult);
uint32_t ecall_ld(uint32_t rs_id_1, uint32_t rs_id_2, int* ldResult);
uint32_t ecall_catt(uint32_t rs_id, int* cattResult);
uint32_t ecall_fet(uint32_t rs_id, int* fetResult);
void ecall_add_encryption_key(const char* strFileNameHash, uint8_t encrypted_encryption_key[32]);

sgx_status_t SGX_CDECL print_string_ocall(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
