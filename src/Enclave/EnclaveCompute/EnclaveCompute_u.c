#include "EnclaveCompute_u.h"
#include <errno.h>

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_generate_response_t {
	uint32_t ms_retval;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
	uint32_t ms_session_id;
} ms_generate_response_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_t;

typedef struct ms_ecall_decrypt_process_t {
	const char* ms_strFileNameHash;
	uint8_t* ms_ciphertext;
	uint32_t ms_len_data;
} ms_ecall_decrypt_process_t;

typedef struct ms_ecall_hwe_t {
	uint32_t ms_retval;
	uint32_t ms_rs_id;
	int* ms_hweResult;
} ms_ecall_hwe_t;

typedef struct ms_ecall_ld_t {
	uint32_t ms_retval;
	uint32_t ms_rs_id_1;
	uint32_t ms_rs_id_2;
	int* ms_ldResult;
} ms_ecall_ld_t;

typedef struct ms_ecall_catt_t {
	uint32_t ms_retval;
	uint32_t ms_rs_id;
	int* ms_cattResult;
} ms_ecall_catt_t;

typedef struct ms_ecall_fet_t {
	uint32_t ms_retval;
	uint32_t ms_rs_id;
	int* ms_fetResult;
} ms_ecall_fet_t;

typedef struct ms_ecall_add_encryption_key_t {
	const char* ms_strFileNameHash;
	uint8_t* ms_encrypted_encryption_key;
} ms_ecall_add_encryption_key_t;

typedef struct ms_print_string_ocall_t {
	const char* ms_str;
} ms_print_string_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL EnclaveCompute_print_string_ocall(void* pms)
{
	ms_print_string_ocall_t* ms = SGX_CAST(ms_print_string_ocall_t*, pms);
	print_string_ocall(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveCompute_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[10];
} ocall_table_EnclaveCompute = {
	10,
	{
		(void*)EnclaveCompute_print_string_ocall,
		(void*)EnclaveCompute_sgx_oc_cpuidex,
		(void*)EnclaveCompute_sgx_thread_wait_untrusted_event_ocall,
		(void*)EnclaveCompute_sgx_thread_set_untrusted_event_ocall,
		(void*)EnclaveCompute_sgx_thread_setwait_untrusted_events_ocall,
		(void*)EnclaveCompute_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)EnclaveCompute_u_sgxssl_ftime,
		(void*)EnclaveCompute_pthread_wait_timeout_ocall,
		(void*)EnclaveCompute_pthread_create_ocall,
		(void*)EnclaveCompute_pthread_wakeup_ocall,
	}
};
sgx_status_t session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status;
	ms_session_request_t ms;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status;
	ms_exchange_report_t ms;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_response(sgx_enclave_id_t eid, uint32_t* retval, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, uint32_t session_id)
{
	sgx_status_t status;
	ms_generate_response_t ms;
	ms.ms_req_message = req_message;
	ms.ms_req_message_size = req_message_size;
	ms.ms_max_payload_size = max_payload_size;
	ms.ms_resp_message = resp_message;
	ms.ms_resp_message_size = resp_message_size;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t end_session(sgx_enclave_id_t eid, uint32_t* retval, uint32_t session_id)
{
	sgx_status_t status;
	ms_end_session_t ms;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_decrypt_process(sgx_enclave_id_t eid, const char* strFileNameHash, uint8_t* ciphertext, uint32_t len_data)
{
	sgx_status_t status;
	ms_ecall_decrypt_process_t ms;
	ms.ms_strFileNameHash = strFileNameHash;
	ms.ms_ciphertext = ciphertext;
	ms.ms_len_data = len_data;
	status = sgx_ecall(eid, 4, &ocall_table_EnclaveCompute, &ms);
	return status;
}

sgx_status_t ecall_hwe(sgx_enclave_id_t eid, uint32_t* retval, uint32_t rs_id, int* hweResult)
{
	sgx_status_t status;
	ms_ecall_hwe_t ms;
	ms.ms_rs_id = rs_id;
	ms.ms_hweResult = hweResult;
	status = sgx_ecall(eid, 5, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ld(sgx_enclave_id_t eid, uint32_t* retval, uint32_t rs_id_1, uint32_t rs_id_2, int* ldResult)
{
	sgx_status_t status;
	ms_ecall_ld_t ms;
	ms.ms_rs_id_1 = rs_id_1;
	ms.ms_rs_id_2 = rs_id_2;
	ms.ms_ldResult = ldResult;
	status = sgx_ecall(eid, 6, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_catt(sgx_enclave_id_t eid, uint32_t* retval, uint32_t rs_id, int* cattResult)
{
	sgx_status_t status;
	ms_ecall_catt_t ms;
	ms.ms_rs_id = rs_id;
	ms.ms_cattResult = cattResult;
	status = sgx_ecall(eid, 7, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_fet(sgx_enclave_id_t eid, uint32_t* retval, uint32_t rs_id, int* fetResult)
{
	sgx_status_t status;
	ms_ecall_fet_t ms;
	ms.ms_rs_id = rs_id;
	ms.ms_fetResult = fetResult;
	status = sgx_ecall(eid, 8, &ocall_table_EnclaveCompute, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_add_encryption_key(sgx_enclave_id_t eid, const char* strFileNameHash, uint8_t encrypted_encryption_key[32])
{
	sgx_status_t status;
	ms_ecall_add_encryption_key_t ms;
	ms.ms_strFileNameHash = strFileNameHash;
	ms.ms_encrypted_encryption_key = (uint8_t*)encrypted_encryption_key;
	status = sgx_ecall(eid, 9, &ocall_table_EnclaveCompute, &ms);
	return status;
}

