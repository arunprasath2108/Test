#ifndef CRYPTO_U_H
#define CRYPTO_U_H
 
 
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>

#include "../App.h"

 
void AES256Encrypt(const uint8_t* plaintext, size_t plaintext_size, const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag);
RSA* GenerateRSAKeyPair(const BIGNUM** modulus, const BIGNUM** publicExponent);
bool RSADecrypt(RSA* rsa_private_key, const unsigned char* encrypted_data, int encrypted_len, unsigned char** decrypted_data, int* decrypted_len);

#endif