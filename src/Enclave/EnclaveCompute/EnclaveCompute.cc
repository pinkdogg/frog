#include "EnclaveCompute_t.h"
#include "EnclaveCompute.h"
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <cstring>
#include <string>
#include "Utility_E2.h"
#include <math.h>
#include <algorithm>
#include <stdlib.h>
#include "error_codes.h"
#include <openssl/evp.h>
#include "sgx_tseal.h"

std::map<std::string, std::map<uint32_t, element>> records;
std::map<std::string, uint8_t*> keys;
uint32_t recordSize = 0;

uint8_t* serialized_keys = nullptr;
uint32_t serialized_size = 0;
char aad_mac_text[BUFSIZ] = "aad mac text";


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

uint32_t ecall_get_sealed_data_size()
{
	if(serialized_keys == nullptr) {
		// serialize the keys
		serialized_size = keys.size() * (64 + 32);
		serialized_keys = (uint8_t*)malloc(serialized_size);
		uint8_t* p = serialized_keys;
		for(auto r : keys) {
			memcpy(p, r.first.c_str(), r.first.size());
			p += r.first.size();
			memcpy(p, r.second, 32);
			p += 32;
		}
	}
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), serialized_size);
}

sgx_status_t ecall_seal_data(uint8_t* sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), serialized_size);
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, serialized_size, serialized_keys, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t ecall_unseal_data(const uint8_t *sealed_blob, size_t data_size)
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

    for(uint8_t* p = decrypt_data; p != decrypt_data + decrypt_data_len; p += 64+32) {
		std::string k = std::string((char*)p, 64);
		uint8_t* v = (uint8_t*)malloc(32);
		memcpy(v, p+64, 32);
		keys[k] = v;
		printf("%s-", k.c_str());
		for(int i = 0; i < 32; i++) {
			printf("%x", keys[k][i]);
		}
		printf("\n");
	}

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}

void DecryptWithKey(uint8_t* ciphertext, const uint32_t dataSize, uint8_t* plaintext, const uint8_t* key) {
	int plainLen;
    int len;
	EVP_CIPHER_CTX* cipherCTX = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(cipherCTX, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(cipherCTX, EVP_CTRL_AEAD_SET_IVLEN, kCRYPTO_BLOCK_SIZE, NULL);
	if (!EVP_DecryptInit_ex(cipherCTX, NULL, NULL,
		key, iv)) {
		printf("CryptoTool: Init error.\n");
	}
	EVP_DecryptUpdate(cipherCTX, NULL, &plainLen, gcm_aad, sizeof(gcm_aad));

    // decrypt the plaintext
    if (!EVP_DecryptUpdate(cipherCTX, plaintext, &plainLen, ciphertext, 
        dataSize)) {
        printf("CryptoTool: Decrypt error.\n");
    }

    EVP_DecryptFinal_ex(cipherCTX, plaintext + plainLen, &len);
    
    plainLen += len;

    if (plainLen != dataSize) {
        printf("CryptoTool: Decrypt output size not equal to origin size.\n");
	}

	EVP_CIPHER_CTX_free(cipherCTX);
}

void ecall_decrypt_process(const char* strFileNameHash, uint8_t* ciphertext, uint32_t len_data) {
	SNP* snp;
	element e;
	uint8_t* plaintext = (uint8_t*)malloc(len_data);

	std::string hash(strFileNameHash);
	auto encryption_key = keys[hash];

	DecryptWithKey(ciphertext, len_data, plaintext, encryption_key);
	
	for(uint8_t* p = plaintext; p != plaintext+len_data; p += sizeof(SNP)) {
		snp = (SNP*)p;
		// if(records.find(snp->rs_id_int) != records.end()) {
        // 	printf("duplicate.\n");
    	// }
		memcpy(e.counters, snp->counters, sizeof(e.counters));
		memcpy(e.data, snp->data, sizeof(e.data));
		
		records[strFileNameHash].insert(std::make_pair(snp->rs_id_int, e));
		// printf("rs%u %u %u %u %u\n", snp->rs_id_int, snp->counters[0], snp->counters[1], snp->counters[2], snp->counters[3]);
		++recordSize;
	}
	free(plaintext);
	// printf("size of records:%d\n", records.size());
	printf("EnclaveCompute:current size of records:%u\n", recordSize);
}

void ecall_add_encryption_key(const char* strFileNameHash, uint8_t encrypted_encryption_key[32]) {
	// use mk/vk to decrypt the encrypted_encryption_key
	std::string hash(strFileNameHash);
	records[hash] = std::map<uint32_t, element>();
	// don't forget to free
	uint8_t* tmp = (uint8_t*)malloc(32);
	memcpy(tmp, encrypted_encryption_key, 32);
	keys[hash] = tmp;
}

bool searchReocrd(uint32_t rs_id, element& e) {
	for(auto r : records) {
		if(r.second.find(rs_id) != r.second.end()) {
			e = r.second[rs_id];
			// todo
			// r.first query enclave_budget
			return true;
		}
	}
    return false;
}

/* Function Description:
*       HWE
*   return 0 secceed
            1 failed
*/
uint32_t ecall_hwe(uint32_t rs_id, int* hweResult) {
	element e;

	if(!searchReocrd(rs_id, e)) {
		return 1;
	}

    //printf("HWE processing starts \n");
	//step 1. decrypt n_AA, n_Aa, n_aa and get sum n
	int N_AA_d = e.counters[0];
	//printf("%d \n", N_AA_d);
	int N_Aa_d = e.counters[1] + e.counters[2];
	//printf("%d \n", N_Aa_d);
	int N_aa_d = e.counters[3];
	//printf("%d \n", N_aa_d);

	int N = N_AA_d + N_Aa_d + N_aa_d;

	//step 2. P_A = (n_AA/n)+(0.5*(n_Aa/n))  Then, P_a = 1 - P_A
	float P_A = (N_AA_d/(float)N) + (0.5*(N_Aa_d/N));
	float P_a = 1.0 - P_A;
	//printf("%f %f \n", P_A, P_a);

	//step 3. Expected counts of AA= nP_A^2, Aa=2*nP_AP_a, aa=nP_a^2
	float N_AA_exp = N*P_A*P_A;
	float N_Aa_exp = 2*N*P_A*P_a;
	float N_aa_exp = N*P_a*P_a;

	//step 4. Pearson goodness of fit test 
	float chi_square = (pow((N_AA_d - N_AA_exp), 2)/N_AA_exp) + (pow((N_Aa_d - N_Aa_exp), 2)/N_Aa_exp) + (pow((N_aa_d - N_aa_exp), 2)/N_aa_exp);
	//printf("%f \n", chi_square);

	//0 for hwe doe not hold, 1 for hwe holds
	//hweResult = (chi_square >= 3.841)? "0":"1";
	*hweResult = (chi_square >= 3.841)? 0:1;

	//printf("%s \n",hweResult);
    return 0;
}

uint32_t ecall_ld(uint32_t rs_id_1, uint32_t rs_id_2, int* ldResult) {
    // printf("map size = %d rs_id_1 = %u rs_id_2 = %u\n", records.size(), rs_id_1, rs_id_2);

    element e1, e2;
	if(!searchReocrd(rs_id_1, e1) || !searchReocrd(rs_id_2, e2)) {
		return 1;
	}

    int counters[4] = {0, 0, 0, 0};
    uint8_t mask;
    int x;
    for(int i = 0; i < sizeof(e1.data); i++) {
        for(int j = 0; j < 8; j++) {
            mask = (uint8_t)0x80 >> j;
            x = ((e1.data[i] & mask) >> (7 - j))*2 + ((e2.data[i] & mask) >> (7 - j));
            ++counters[x];
        }
    }
	int N_AB_d = counters[0];
	//printf("%d \n", N_AB_d);

	int N_Ab_d = counters[1];
	//printf("%d \n", N_Ab_d);

	int N_aB_d = counters[2];
	//printf("%d \n", N_aB_d);

	int N_ab_d = counters[3];
	//printf("%d \n", N_ab_d);

	//2. sum these values to find N

	int N = N_AB_d + N_Ab_d + N_aB_d + N_ab_d;
	//printf("%d \n", N);

	//3. find the frequencies P_AB, P_Ab, P_aB, P_ab.
	float P_AB = N_AB_d/(float)N;
	float P_Ab = N_Ab_d/(float)N;
	float P_aB = N_aB_d/(float)N;
	float P_ab = N_ab_d/(float)N;
	//printf("%f %f %f %f \n", P_AB, P_Ab, P_aB, P_ab);

	//4. Calculate D = P_AB*P_ab - P_aB*P_Ab
	float D = P_AB*P_ab - P_aB*P_Ab;
	//printf("%f \n", D);

	//5. P_A = P_AB + P_Ab, P_a = BigInteger.one - P_A
	//   P_B = P_AB + P_aB, P_b = BigInteger.one - P_B
	float P_A = P_AB + P_Ab;
	float P_B = P_AB + P_aB;

	//printf("%f %f \n", P_A, P_B);

	//6. If D>0, D_max = min(P_A*P_b, P_a*P_B)
	//	 else,   D_max = min(P_A*P_B, P_a*P_b)
	float D_max;
	if(D > 0)
	{
		D_max = P_A*(1 - P_B) <= (1 - P_A)*P_B ? P_A*(1 - P_B): (1 - P_A)*P_B;
		//printf("greater than 0 \n");
	}
	else
	{
		D_max = P_A*P_B <= (1 - P_A)*(1 - P_B) ? P_A*P_B : (1 - P_A)*(1 - P_B);
		//printf("not greater than 0 \n");
	}


	//7. D' = D/D_max
	float D_prime = abs(D/D_max);
	//printf("%f \n", D_prime);

	//memcpy(ldResult, input[0], strlen(input[0]) + 1);
	*ldResult = (D_prime == 0.0)? 0:1;
    return 0;
}

uint32_t ecall_catt(uint32_t rs_id, int* cattResult) {
    //printf("CATT processing starts \n");

	element e;
	if(!searchReocrd(rs_id, e)) {
		return 1;
	}

    int N_AA_case_d, N_Aa_case_d, N_aa_case_d;
    
    uint8_t x, mask;
    for(int i = 0; i < 273/2; i++) {
        for(int j = 0; j < 4; j++) {
            mask = 0b11000000 >> (2 * j);
            x = (e.data[i] & mask) >> (2 * (3 - j));
            switch (x)
            {
                case 0:
                    ++N_AA_case_d;
                    break;
                case 1:
                case 2:
                    ++N_Aa_case_d;
                    break;
                case 3:
                    ++N_aa_case_d;
                    break;
                default:
                    break;
            }
        }
    }
    int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

    int N_AA_control_d, N_Aa_control_d, N_aa_control_d;
    for(int i = 273/2; i < 273; i++) {
        for(int j = 0; j < 4; j++) {
            mask = 0b11000000 >> (2 * j);
            x = (e.data[i] & mask) >> (2 * (3 - j));
            switch (x)
            {
                case 0:
                    ++N_AA_control_d;
                    break;
                case 1:
                case 2:
                    ++N_Aa_control_d;
                    break;
                case 3:
                    ++N_aa_control_d;
                    break;
                default:
                    break;
            }
        }
    }

	int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
	int sum = case_sum + control_sum;

	//codominant model (0,1,2) 
	float weight1 = 0.0;
	float weight2 = 1.0;
	float weight3 = 2.0;

	float T = weight1*(N_AA_control_d*case_sum - N_AA_case_d*control_sum) +
		weight2*(N_Aa_control_d*case_sum - N_Aa_case_d*control_sum) +
		weight3*(N_aa_control_d*case_sum - N_aa_case_d*control_sum);

	int AA_sum = N_AA_case_d + N_AA_control_d;
	int Aa_sum = N_Aa_case_d + N_Aa_control_d;
	int aa_sum = N_aa_case_d + N_aa_control_d;

	float var_T = ((control_sum * case_sum)/(float)(control_sum + case_sum))*
		(
		(
		(weight1*weight1)*(sum - AA_sum)*AA_sum +
		(weight2*weight2)*(sum - Aa_sum)*Aa_sum +
		(weight3*weight3)*(sum - aa_sum)*aa_sum 
		)
		-
		(2*((pow(weight1, 2)*pow(weight2, 2)*AA_sum*Aa_sum) + ((pow(weight2, 2)*pow(weight2, 2)*Aa_sum*aa_sum))))
		);
	float chi_square = (T*T)/var_T;
	//printf("%f", chi_square);

	//df = 1, critical chi_square value = 3.841
	//null hypothesis: no trend 
	//cattResult = (chi_square >= 3.841)? "1":"0";
	*cattResult = (chi_square >= 3.841)? 1:0;
	//printf("%s \n",cattResult);

    return 0;
}

unsigned long long int factorial(unsigned long long int n) 
{
	if (n == 0)
		return 1;
	return n * factorial(n - 1);
}

int32_t fisher23_tailsum(double* base_probp, double* saved12p, double* saved13p, double* saved22p, double* saved23p, double *totalp, uint32_t* tie_ctp, uint32_t right_side) {
	double total = 0;
	double cur_prob = *base_probp;
	double tmp12 = *saved12p;
	double tmp13 = *saved13p;
	double tmp22 = *saved22p;
	double tmp23 = *saved23p;
	double tmps12;
	double tmps13;
	double tmps22;
	double tmps23;
	double prev_prob;
	// identify beginning of tail
	if (right_side) {
		if (cur_prob > EXACT_TEST_BIAS) {
			prev_prob = tmp13 * tmp22;
			while (prev_prob > 0.5) {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= prev_prob / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					break;
				}
				prev_prob = tmp13 * tmp22;
			}
			*base_probp = cur_prob;
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
		} else {
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
			while (1) {
				prev_prob = cur_prob;
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
				if (cur_prob < prev_prob) {
					return 1;
				}
				tmp12 -= 1;
				tmp23 -= 1;
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					// throw in extra (1 - SMALL_EPSILON) multiplier to prevent rounding
					// errors from causing this to keep going when the left-side test
					// stopped
					if (cur_prob > (1 - SMALL_EPSILON) * EXACT_TEST_BIAS) {
						break;
					}
					*tie_ctp += 1;
				}
				total += cur_prob;
			}
			prev_prob = cur_prob;
			cur_prob = *base_probp;
			*base_probp = prev_prob;
		}
	} else {
		if (cur_prob > EXACT_TEST_BIAS) {
			prev_prob = tmp12 * tmp23;
			while (prev_prob > 0.5) {
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= prev_prob / (tmp13 * tmp22);
				tmp12 -= 1;
				tmp23 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					break;
				}
				prev_prob = tmp12 * tmp23;
			}
			*base_probp = cur_prob;
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
		} else {
			tmps12 = tmp12;
			tmps13 = tmp13;
			tmps22 = tmp22;
			tmps23 = tmp23;
			while (1) {
				prev_prob = cur_prob;
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
				if (cur_prob < prev_prob) {
					return 1;
				}
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					if (cur_prob > EXACT_TEST_BIAS) {
						break;
					}
					*tie_ctp += 1;
				}
				total += cur_prob;
			}
			prev_prob = cur_prob;
			cur_prob = *base_probp;
			*base_probp = prev_prob;
		}
	}
	*saved12p = tmp12;
	*saved13p = tmp13;
	*saved22p = tmp22;
	*saved23p = tmp23;
	if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
		if (cur_prob > EXACT_TEST_BIAS) {
			// even most extreme table on this side is too probable
			*totalp = 0;
			return 0;
		}
		*tie_ctp += 1;
	}
	// sum tail to floating point precision limit
	if (right_side) {
		prev_prob = total;
		total += cur_prob;
		while (total > prev_prob) {
			tmps12 += 1;
			tmps23 += 1;
			cur_prob *= (tmps13 * tmps22) / (tmps12 * tmps23);
			tmps13 -= 1;
			tmps22 -= 1;
			prev_prob = total;
			total += cur_prob;
		}
	} else {
		prev_prob = total;
		total += cur_prob;
		while (total > prev_prob) {
			tmps13 += 1;
			tmps22 += 1;
			cur_prob *= (tmps12 * tmps23) / (tmps13 * tmps22);
			tmps12 -= 1;
			tmps23 -= 1;
			prev_prob = total;
			total += cur_prob;
		}
	}
	*totalp = total;
	return 0;
}

double fisher23(uint32_t m11, uint32_t m12, uint32_t m13, uint32_t m21, uint32_t m22, uint32_t m23, uint32_t midp) {
	// 2x3 Fisher-Freeman-Halton exact test p-value calculation.
	// The number of tables involved here is still small enough that the network
	// algorithm (and the improved variants thereof that I've seen) are
	// suboptimal; a 2-dimensional version of the SNPHWE2 strategy has higher
	// performance.
	// 2x4, 2x5, and 3x3 should also be practical with this method, but beyond
	// that I doubt it's worth the trouble.
	// Complexity of approach is O(n^{df/2}), where n is number of observations.
	double cur_prob = (1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS;
	double tprob = cur_prob;
	double cprob = 0;
	double dyy = 0;
	uint32_t tie_ct = 1;
	uint32_t dir = 0; // 0 = forwards, 1 = backwards
	double base_probl;
	double base_probr;
	double orig_base_probl;
	double orig_base_probr;
	double orig_row_prob;
	double row_prob;
	uint32_t uii;
	uint32_t ujj;
	uint32_t ukk;
	double cur11;
	double cur21;
	double savedl12;
	double savedl13;
	double savedl22;
	double savedl23;
	double savedr12;
	double savedr13;
	double savedr22;
	double savedr23;
	double orig_savedl12;
	double orig_savedl13;
	double orig_savedl22;
	double orig_savedl23;
	double orig_savedr12;
	double orig_savedr13;
	double orig_savedr22;
	double orig_savedr23;
	double tmp12;
	double tmp13;
	double tmp22;
	double tmp23;
	double dxx;
	double preaddp;
	// Ensure m11 + m21 <= m12 + m22 <= m13 + m23.
	uii = m11 + m21;
	ujj = m12 + m22;
	if (uii > ujj) {
		ukk = m11;
		m11 = m12;
		m12 = ukk;
		ukk = m21;
		m21 = m22;
		m22 = ukk;
		ukk = uii;
		uii = ujj;
		ujj = ukk;
	}
	ukk = m13 + m23;
	if (ujj > ukk) {
		ujj = ukk;
		ukk = m12;
		m12 = m13;
		m13 = ukk;
		ukk = m22;
		m22 = m23;
		m23 = ukk;
	}
	if (uii > ujj) {
		ukk = m11;
		m11 = m12;
		m12 = ukk;
		ukk = m21;
		m21 = m22;
		m22 = ukk;
	}
	// Ensure majority of probability mass is in front of m11.
	if ((((uint64_t)m11) * (m22 + m23)) > (((uint64_t)m21) * (m12 + m13))) {
		ukk = m11;
		m11 = m21;
		m21 = ukk;
		ukk = m12;
		m12 = m22;
		m22 = ukk;
		ukk = m13;
		m13 = m23;
		m23 = ukk;
	}
	if ((((uint64_t)m12) * m23) > (((uint64_t)m13) * m22)) {
		base_probr = cur_prob;
		savedr12 = m12;
		savedr13 = m13;
		savedr22 = m22;
		savedr23 = m23;
		tmp12 = savedr12;
		tmp13 = savedr13;
		tmp22 = savedr22;
		tmp23 = savedr23;
		// m12 and m23 must be nonzero
		dxx = tmp12 * tmp23;
		do {
			tmp13 += 1;
			tmp22 += 1;
			cur_prob *= dxx / (tmp13 * tmp22);
			tmp12 -= 1;
			tmp23 -= 1;
			if (cur_prob <= EXACT_TEST_BIAS) {
				if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
					tie_ct++;
				}
				tprob += cur_prob;
				break;
			}
			cprob += cur_prob;
			if (cprob == INFINITY) {
				return 0;
			}
			dxx = tmp12 * tmp23;
			// must enforce tmp12 >= 0 and tmp23 >= 0 since we're saving these
		} while (dxx > 0.5);
		savedl12 = tmp12;
		savedl13 = tmp13;
		savedl22 = tmp22;
		savedl23 = tmp23;
		base_probl = cur_prob;
		do {
			tmp13 += 1;
			tmp22 += 1;
			cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
			tmp12 -= 1;
			tmp23 -= 1;
			preaddp = tprob;
			tprob += cur_prob;
		} while (tprob > preaddp);
		tmp12 = savedr12;
		tmp13 = savedr13;
		tmp22 = savedr22;
		tmp23 = savedr23;
		cur_prob = base_probr;
		do {
			tmp12 += 1;
			tmp23 += 1;
			cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
			tmp13 -= 1;
			tmp22 -= 1;
			preaddp = tprob;
			tprob += cur_prob;
		} while (tprob > preaddp);
	} else {
		base_probl = cur_prob;
		savedl12 = m12;
		savedl13 = m13;
		savedl22 = m22;
		savedl23 = m23;
		if (!((((uint64_t)m12) * m23) + (((uint64_t)m13) * m22))) {
			base_probr = cur_prob;
			savedr12 = savedl12;
			savedr13 = savedl13;
			savedr22 = savedl22;
			savedr23 = savedl23;
		} else {
			tmp12 = savedl12;
			tmp13 = savedl13;
			tmp22 = savedl22;
			tmp23 = savedl23;
			dxx = tmp13 * tmp22;
			do {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= dxx / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				if (cur_prob <= EXACT_TEST_BIAS) {
					if (cur_prob > (1 - 2 * SMALLISH_EPSILON) * EXACT_TEST_BIAS) {
						tie_ct++;
					}
					tprob += cur_prob;
					break;
				}
				cprob += cur_prob;
				if (cprob == INFINITY) {
					return 0;
				}
				dxx = tmp13 * tmp22;
			} while (dxx > 0.5);
			savedr12 = tmp12;
			savedr13 = tmp13;
			savedr22 = tmp22;
			savedr23 = tmp23;
			base_probr = cur_prob;
			do {
				tmp12 += 1;
				tmp23 += 1;
				cur_prob *= (tmp13 * tmp22) / (tmp12 * tmp23);
				tmp13 -= 1;
				tmp22 -= 1;
				preaddp = tprob;
				tprob += cur_prob;
			} while (tprob > preaddp);
			tmp12 = savedl12;
			tmp13 = savedl13;
			tmp22 = savedl22;
			tmp23 = savedl23;
			cur_prob = base_probl;
			do {
				tmp13 += 1;
				tmp22 += 1;
				cur_prob *= (tmp12 * tmp23) / (tmp13 * tmp22);
				tmp12 -= 1;
				tmp23 -= 1;
				preaddp = tprob;
				tprob += cur_prob;
			} while (tprob > preaddp);
		}
	}
	row_prob = tprob + cprob;
	orig_base_probl = base_probl;
	orig_base_probr = base_probr;
	orig_row_prob = row_prob;
	orig_savedl12 = savedl12;
	orig_savedl13 = savedl13;
	orig_savedl22 = savedl22;
	orig_savedl23 = savedl23;
	orig_savedr12 = savedr12;
	orig_savedr13 = savedr13;
	orig_savedr22 = savedr22;
	orig_savedr23 = savedr23;
	for (; dir < 2; dir++) {
		cur11 = m11;
		cur21 = m21;
		if (dir) {
			base_probl = orig_base_probl;
			base_probr = orig_base_probr;
			row_prob = orig_row_prob;
			savedl12 = orig_savedl12;
			savedl13 = orig_savedl13;
			savedl22 = orig_savedl22;
			savedl23 = orig_savedl23;
			savedr12 = orig_savedr12;
			savedr13 = orig_savedr13;
			savedr22 = orig_savedr22;
			savedr23 = orig_savedr23;
			ukk = m11;
			if (ukk > m22 + m23) {
				ukk = m22 + m23;
			}
		} else {
			ukk = m21;
			if (ukk > m12 + m13) {
				ukk = m12 + m13;
			}
		}
		ukk++;
		while (--ukk) {
			if (dir) {
				cur21 += 1;
				if (savedl23) {
					savedl13 += 1;
					row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
					base_probl *= (cur11 * savedl23) / (cur21 * savedl13);
					savedl23 -= 1;
				} else {
					savedl12 += 1;
					row_prob *= (cur11 * (savedl22 + savedl23)) / (cur21 * (savedl12 + savedl13));
					base_probl *= (cur11 * savedl22) / (cur21 * savedl12);
					savedl22 -= 1;
				}
				cur11 -= 1;
			} else {
				cur11 += 1;
				if (savedl12) {
					savedl22 += 1;
					row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
					base_probl *= (cur21 * savedl12) / (cur11 * savedl22);
					savedl12 -= 1;
				} else {
					savedl23 += 1;
					row_prob *= (cur21 * (savedl12 + savedl13)) / (cur11 * (savedl22 + savedl23));
					base_probl *= (cur21 * savedl13) / (cur11 * savedl23);
					savedl13 -= 1;
				}
				cur21 -= 1;
			}
			if (fisher23_tailsum(&base_probl, &savedl12, &savedl13, &savedl22, &savedl23, &dxx, &tie_ct, 0)) {
				break;
			}
			tprob += dxx;
			if (dir) {
				if (savedr22) {
					savedr12 += 1;
					base_probr *= ((cur11 + 1) * savedr22) / (cur21 * savedr12);
					savedr22 -= 1;
				} else {
					savedr13 += 1;
					base_probr *= ((cur11 + 1) * savedr23) / (cur21 * savedr13);
					savedr23 -= 1;
				}
			} else {
				if (savedr13) {
					savedr23 += 1;
					base_probr *= ((cur21 + 1) * savedr13) / (cur11 * savedr23);
					savedr13 -= 1;
				} else {
					savedr22 += 1;
					base_probr *= ((cur21 + 1) * savedr12) / (cur11 * savedr22);
					savedr12 -= 1;
				}
			}
			fisher23_tailsum(&base_probr, &savedr12, &savedr13, &savedr22, &savedr23, &dyy, &tie_ct, 1);
			tprob += dyy;
			cprob += row_prob - dxx - dyy;
			if (cprob == INFINITY) {
				return 0;
			}
		}
		if (!ukk) {
			continue;
		}
		savedl12 += savedl13;
		savedl22 += savedl23;
		if (dir) {
			while (1) {
				preaddp = tprob;
				tprob += row_prob;
				if (tprob <= preaddp) {
					break;
				}
				cur21 += 1;
				savedl12 += 1;
				row_prob *= (cur11 * savedl22) / (cur21 * savedl12);
				cur11 -= 1;
				savedl22 -= 1;
			}
		} else {
			while (1) {
				preaddp = tprob;
				tprob += row_prob;
				if (tprob <= preaddp) {
					break;
				}
				cur11 += 1;
				savedl22 += 1;
				row_prob *= (cur21 * savedl12) / (cur11 * savedl22);
				cur21 -= 1;
				savedl12 -= 1;
			}
		}
	}
	if (!midp) {
		return tprob / (tprob + cprob);
	} else {
		return (tprob - ((1 - SMALLISH_EPSILON) * EXACT_TEST_BIAS * 0.5) * ((int32_t)tie_ct)) / (tprob + cprob);
	}
}

uint32_t ecall_fet(uint32_t rs_id, int* fetResult) {
    //printf("FET processing starts \n");

    element e;
	if(!searchReocrd(rs_id, e)) {
		return 1;
	}

    int N_AA_case_d, N_Aa_case_d, N_aa_case_d;
    
    uint8_t x, mask;
    for(int i = 0; i < 273/2; i++) {
        for(int j = 0; j < 4; j++) {
            mask = 0b11000000 >> (2 * j);
            x = (e.data[i] & mask) >> (2 * (3 - j));
            switch (x)
            {
                case 0:
                    ++N_AA_case_d;
                    break;
                case 1:
                case 2:
                    ++N_Aa_case_d;
                    break;
                case 3:
                    ++N_aa_case_d;
                    break;
                default:
                    break;
            }
        }
    }
    int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

    int N_AA_control_d, N_Aa_control_d, N_aa_control_d;
    for(int i = 273/2; i < 273; i++) {
        for(int j = 0; j < 4; j++) {
            mask = 0b11000000 >> (2 * j);
            x = (e.data[i] & mask) >> (2 * (3 - j));
            switch (x)
            {
                case 0:
                    ++N_AA_control_d;
                    break;
                case 1:
                case 2:
                    ++N_Aa_control_d;
                    break;
                case 3:
                    ++N_aa_control_d;
                    break;
                default:
                    break;
            }
        }
    }

	int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
	int sum = case_sum + control_sum;


	int AA_sum = N_AA_case_d + N_AA_control_d;
	int Aa_sum = N_Aa_case_d + N_Aa_control_d;
	int aa_sum = N_aa_case_d + N_aa_control_d;

	//int lob = factorial(case_sum)*factorial(control_sum) * factorial(AA_sum) * factorial(Aa_sum) * factorial(aa_sum);
	//int hor = factorial(N_AA_control_d) * factorial(N_Aa_control_d) * factorial(N_aa_control_d) * factorial(N_AA_case_d) * factorial(N_Aa_case_d) * factorial(N_aa_case_d) * factorial(sum);
	int denominator = factorial(5)* factorial(4)*factorial(3)*factorial(3)*factorial(3);
	int numerator = factorial(1)*factorial(2)*factorial(2)*factorial(2)*factorial(1)*factorial(1)*factorial(19);
	//float p_value = fisher23(70,20,10,40,30,30,0);  //denominator/(float)numerator;
	//float p_value = fisher23(0,3,2,6,5,1,0);

	float p_value = fisher23(N_AA_control_d, N_Aa_control_d, N_aa_control_d, N_AA_case_d, N_Aa_case_d, N_aa_case_d, 0);

	//float p_value = (factorial(case_sum) * factorial(control_sum) * factorial(AA_sum) * factorial(Aa_sum) * factorial(aa_sum)) / (float)(factorial(N_AA_control_d) * factorial(N_Aa_control_d)
	//* factorial(N_aa_control_d) * factorial(N_AA_case_d) * factorial(N_Aa_case_d) * factorial(N_aa_case_d) * factorial(sum));
	//float p_value = (double)(factorial(20) * factorial(2) * factorial(1) * factorial(2) * factorial(2)) / (double)(factorial(3) * factorial(4)
	//* factorial(4) * factorial(4) * factorial(4) * factorial(4) * factorial(4));

	//printf("%f \n", p_value);


	//df = 1, critical chi_square value = 3.841
	//null hypothesis: no statistical association between genotype and disease
	//fetResult = (p_value < 0.05)? "1":"0";
	*fetResult = (p_value < 0.05)? 1:0;
	//printf("%s \n",fetResult);

    return 0;
}

/* Function Description:
 *   this is to verify peer enclave's identity
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable that it should be INITIALIZED and without DEBUG attribute (except the project is built with DEBUG option)
 * */
extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_initiator_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
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
