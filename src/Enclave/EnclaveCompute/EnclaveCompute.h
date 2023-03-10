#ifndef _ENCLAVECOMPUTE_H_
#define _ENCLAVECOMPUTE_H_
#include <map>

#define UNUSED(val) (void)(val)

/* --------for Fisher Exact Test function from : https://github.com/chrchang/stats/blob/master/fisher.c  --------*/
#define SMALLISH_EPSILON 0.00000000003
#define SMALL_EPSILON 0.0000000000001

// This helps us avoid premature floating point overflow.
#define EXACT_TEST_BIAS 0.00000000000000000000000010339757656912845935892608650874535669572651386260986328125


std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

// this is expected initiator's MRSIGNER for demonstration purpose
sgx_measurement_t g_initiator_mrsigner = {
	{
			0x9d, 0xc1, 0x26, 0xd1, 0x5b, 0xe4, 0xf1, 0x15, 0x0a, 0x52, 0x0c, 0x03, 0x3c, 0xc1, 0x9b, 0xa8, 
			0x85, 0x24, 0xf6, 0xfb, 0x45, 0x76, 0xb5, 0x07, 0x43, 0xca, 0xd3, 0xb2, 0x54, 0xe2, 0x4b, 0x71     
	}
};

typedef struct SNP {
    uint32_t rs_id_int;
    uint32_t counters[4];
    uint8_t data[273];
}SNP;

typedef struct element {
    uint32_t counters[4];
    uint8_t data[273];
}element;

const uint8_t kAES_256_GCM_KEY[32] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
                                      0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

const uint32_t kCRYPTO_BLOCK_SIZE = 16;
const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};
const uint8_t iv[kCRYPTO_BLOCK_SIZE] = {0, 0, 0, 0, 
										0, 0, 0, 0,
										0, 0, 0, 0,
										0, 0, 0, 0};

#endif