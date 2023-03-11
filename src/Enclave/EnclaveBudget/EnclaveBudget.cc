#include "EnclaveBudget_t.h"
#include "EnclaveBudget.h"
#include <stdarg.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include "dh_session_protocol.h"
#include "error_codes.h"
#include "EnclaveMessageExchange.h"
#include "Utility_E1.h"
#include <stdlib.h>
#include <time.h>
#include <map>

std::map<std::string, uint32_t> privacyBudgetDB;

uint8_t* serialized_db = nullptr;
uint32_t serialized_size = 0;
char aad_mac_text[BUFSIZ] = "aad mac text";

uint32_t ecall_create_session()
{
    return create_session(&g_session);
}

uint32_t ecall_transfer_secret_key() {
    return message_exchange(aes_128bit_key, aes_128bit_key_len);
}

uint32_t ecall_close_session() {
    ATTESTATION_STATUS ke_status = SUCCESS;

    ke_status = close_session(&g_session);

    //Erase the session context
    memset(&g_session, 0, sizeof(dh_session_t));
    return ke_status;
}

int ecall_query_budget(const char* strFileNameHash) {
    std::string fileNameHash(strFileNameHash);
    printf("%s\n", strFileNameHash);
    if(privacyBudgetDB.find(fileNameHash) == privacyBudgetDB.end()) {
        return 1;
    }
    printf("EnclaveBudget:file %s budget, %d\n", strFileNameHash, privacyBudgetDB[fileNameHash]);
    return 0;
}

uint32_t ecall_budget_get_sealed_data_size()
{
	if(serialized_db == nullptr) {
		// serialize the keys
		serialized_size = privacyBudgetDB.size() * (64 + 4);
		serialized_db = (uint8_t*)malloc(serialized_size);
		uint8_t* p = serialized_db;
		for(auto r : privacyBudgetDB) {
			memcpy(p, r.first.c_str(), r.first.size());
			p += r.first.size();
			memcpy(p, &r.second, 4);
			p += 4;
		}
	}
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), serialized_size);
}

sgx_status_t ecall_budget_seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), serialized_size);
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, serialized_size, serialized_db, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t ecall_budget_unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    for(uint8_t* p = decrypt_data; p != decrypt_data + decrypt_data_len; p += 64+4) {
		std::string k = std::string((char*)p, 64);
		uint32_t v = *(uint32_t*)(p+64);
		privacyBudgetDB[k] = v;
		printf("%s - %d\n", k.c_str(), privacyBudgetDB[k]);
	}
    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

void ecall_add_privacy_budget(const char* strFileNameHash, uint32_t encrypted_privacy_budget) {
    // use mk/vk to decrypt encrypted_privacy_budgeet
    std::string hash(strFileNameHash);
    privacyBudgetDB[hash] = encrypted_privacy_budget;
    printf("EnclaveBudget:%s---%u\n", strFileNameHash, encrypted_privacy_budget);
}


uint32_t message_exchange(uint8_t* secret_data, size_t secret_data_size) {
    ATTESTATION_STATUS ke_status = SUCCESS;
    uint32_t target_fn_id, msg_type;
    char* marshalled_inp_buff;
    size_t marshalled_inp_buff_len;
    char* out_buff;
    size_t out_buff_len;
    size_t max_out_buff_size;
    char* secret_response;

    target_fn_id = 0;
    msg_type = MESSAGE_EXCHANGE;
    max_out_buff_size = 50; // it's assumed the maximum payload size in response message is 50 bytes, it's for demonstration purpose

    //Marshals the secret data into a buffer
    // ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, &marshalled_inp_buff, &marshalled_inp_buff_len);
    ke_status = marshal_message_exchange_request(target_fn_id, msg_type, secret_data, secret_data_size, &marshalled_inp_buff, &marshalled_inp_buff_len);

    if(ke_status != SUCCESS)
    {
        return ke_status;
    }

    //Core Reference Code function
    ke_status = send_request_receive_response(&g_session, marshalled_inp_buff,
                                                marshalled_inp_buff_len, max_out_buff_size, &out_buff, &out_buff_len);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    //Un-marshal the secret response data
    ke_status = umarshal_message_exchange_response(out_buff, &secret_response);
    if(ke_status != SUCCESS)
    {
        SAFE_FREE(marshalled_inp_buff);
        SAFE_FREE(out_buff);
        return ke_status;
    }

    SAFE_FREE(marshalled_inp_buff);
    SAFE_FREE(out_buff);
    SAFE_FREE(secret_response);
    return SUCCESS;
}

/* Function Description:
 *   This is to verify peer enclave's identity.
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable: it's INITIALIZED'ed enclave; in non-debug build configuration, the enclave isn't loaded with enclave debug mode.
 **/
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if (!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_responder_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    // check peer enclave's product ID and enclave attribute (should be INITIALIZED'ed)
    if (peer_enclave_identity->isv_prod_id != RESPONDER_PRODID || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;
    // check the enclave isn't loaded in enclave debug mode, except that the project is built for debug purpose
#if defined(NDEBUG)
    if (peer_enclave_identity->attributes.flags & SGX_FLAGS_DEBUG)
    	return ENCLAVE_TRUST_ERROR;
#endif

    return SUCCESS;
}

/* Function Description: Operates on the input secret and generate the output secret
 * */
uint32_t get_message_exchange_response(uint32_t inp_secret_data)
{
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111;

    return secret_response;

}

//Generates the response from the request message
/* Function Description:
 *   process request message and generate response
 * Parameter Description:
 *   [input] decrypted_data: this is pointer to decrypted message
 *   [output] resp_buffer: this is pointer to response message, the buffer is allocated inside this function
 *   [output] resp_length: this points to response length
 * */
extern "C" uint32_t message_exchange_response_generator(char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t inp_secret_data;
    uint32_t out_secret_data;
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    if(umarshal_message_exchange_request(&inp_secret_data,ms) != SUCCESS)
        return ATTESTATION_ERROR;

    out_secret_data = get_message_exchange_response(inp_secret_data);

    if(marshal_message_exchange_response(resp_buffer, resp_length, out_secret_data) != SUCCESS)
        return MALLOC_ERROR;

    return SUCCESS;
}