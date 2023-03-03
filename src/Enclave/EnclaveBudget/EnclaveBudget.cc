#include "EnclaveBudget_t.h"
#include "EnclaveBudget.h"

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "dh_session_protocol.h"
#include "error_codes.h"
#include "EnclaveMessageExchange.h"
#include "Utility_E1.h"
#include <stdlib.h>
#include <time.h>
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

/* Function Description:
 *   This is ECALL routine to create ECDH session.
 *   When it succeeds to create ECDH session, the session context is saved in g_session.
 * */
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

/*
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
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

void ecall_encrypt_data(uint8_t* plaintext, uint8_t* ciphertext, uint32_t len_data) {
    sgx_aes_gcm_data_t *message_aes_gcm_data = (sgx_aes_gcm_data_t *)ciphertext;
    memset(message_aes_gcm_data->reserved, 'a', sizeof(message_aes_gcm_data->reserved));
    const uint8_t* p_aad = (const uint8_t*)(" ");
    uint32_t p_len = 0;
    sgx_status_t status;

    message_aes_gcm_data->payload_size = len_data;
    status = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_128bit_key, plaintext, len_data,
                message_aes_gcm_data->payload, 
                reinterpret_cast<uint8_t*>(&message_aes_gcm_data->reserved), 
                sizeof(message_aes_gcm_data->reserved),
                p_aad, p_len, &message_aes_gcm_data->payload_tag);


    // printf("len_data = %u\n", len_data);
    // printf("plaintext:");
    // for(int i = 0; i < len_data; i++) {
    //     printf("%x ", plaintext[i]);
    // }
    // printf("\n");
    // printf("ciphertext:");
    // for(int i = 0; i < len_data; i++) {
    //     printf("%x ", ciphertext[i]);
    // }
    // printf("\n");
}

void ecall_rencrypt_data(uint8_t* ciphertext, uint32_t len_data) {
    uint8_t iv[12];
    memset(iv, 0, sizeof(iv));
    const uint8_t* p_aad = (const uint8_t*)(" ");
    uint32_t p_len = 0;
    sgx_status_t status;

    uint8_t* plaintext = (uint8_t*)malloc(len_data);

    // use original key to decrypt the data
    status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_128bit_key, 
        ciphertext, len_data, plaintext,
        iv, sizeof(iv), p_aad, p_len, nullptr);
    
    // generate new key
    // srand(time(nullptr));
    // for(int i = 0; i < aes_128bit_key_len; i++) {
    //     aes_128bit_key[i] = rand() % 255;
    // }

    // encrypt the data
    status = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_128bit_key, plaintext, len_data,
                ciphertext, iv, sizeof(iv), p_aad, p_len, nullptr);
}
