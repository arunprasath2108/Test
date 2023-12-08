#ifndef CRYPTO_H
#define CRYPTO_H

#include "../Enclave_t.h"
 
//openssl libraries
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

//sgxssl libraries
#include "sgx_tcrypto.h"
#include "tSgxSSL_api.h"
#include "sgx_thread.h"


int AES256Decrypt(uint8_t* key, uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, uint8_t* iv, uint8_t* tag, int* tag_verification);
bool RSAEncrypt(RSA* rsa_public_key, const unsigned char* plaintext, size_t plaintext_len, unsigned char** encrypted_data, int* encrypted_len);


#endif