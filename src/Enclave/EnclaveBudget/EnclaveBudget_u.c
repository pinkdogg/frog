#include "EnclaveBudget_u.h"
#include <errno.h>

typedef struct ms_ecall_create_session_t {
	uint32_t ms_retval;
} ms_ecall_create_session_t;

typedef struct ms_ecall_transfer_secret_key_t {
	uint32_t ms_retval;
} ms_ecall_transfer_secret_key_t;

typedef struct ms_ecall_close_session_t {
	uint32_t ms_retval;
} ms_ecall_close_session_t;

typedef struct ms_ecall_add_privacy_budget_t {
	const char* ms_strFileNameHash;
	uint32_t ms_encrypted_privacy_budget;
} ms_ecall_add_privacy_budget_t;

typedef struct ms_print_string_ocall_t {
	const char* ms_str;
} ms_print_string_ocall_t;

typedef struct ms_session_request_ocall_t {
	uint32_t ms_retval;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	uint32_t ms_retval;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_ocall_t;

typedef struct ms_send_request_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_send_request_ocall_t;

typedef struct ms_end_session_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_ocall_t;

static sgx_status_t SGX_CDECL EnclaveBudget_print_string_ocall(void* pms)
{
	ms_print_string_ocall_t* ms = SGX_CAST(ms_print_string_ocall_t*, pms);
	print_string_ocall(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveBudget_session_request_ocall(void* pms)
{
	ms_session_request_ocall_t* ms = SGX_CAST(ms_session_request_ocall_t*, pms);
	ms->ms_retval = session_request_ocall(ms->ms_dh_msg1, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveBudget_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_dh_msg2, ms->ms_dh_msg3, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveBudget_send_request_ocall(void* pms)
{
	ms_send_request_ocall_t* ms = SGX_CAST(ms_send_request_ocall_t*, pms);
	ms->ms_retval = send_request_ocall(ms->ms_session_id, ms->ms_req_message, ms->ms_req_message_size, ms->ms_max_payload_size, ms->ms_resp_message, ms->ms_resp_message_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveBudget_end_session_ocall(void* pms)
{
	ms_end_session_ocall_t* ms = SGX_CAST(ms_end_session_ocall_t*, pms);
	ms->ms_retval = end_session_ocall(ms->ms_session_id);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_EnclaveBudget = {
	5,
	{
		(void*)EnclaveBudget_print_string_ocall,
		(void*)EnclaveBudget_session_request_ocall,
		(void*)EnclaveBudget_exchange_report_ocall,
		(void*)EnclaveBudget_send_request_ocall,
		(void*)EnclaveBudget_end_session_ocall,
	}
};
sgx_status_t ecall_create_session(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_ecall_create_session_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveBudget, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_transfer_secret_key(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_ecall_transfer_secret_key_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveBudget, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_close_session(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_ecall_close_session_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveBudget, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_add_privacy_budget(sgx_enclave_id_t eid, const char* strFileNameHash, uint32_t encrypted_privacy_budget)
{
	sgx_status_t status;
	ms_ecall_add_privacy_budget_t ms;
	ms.ms_strFileNameHash = strFileNameHash;
	ms.ms_encrypted_privacy_budget = encrypted_privacy_budget;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveBudget, &ms);
	return status;
}

