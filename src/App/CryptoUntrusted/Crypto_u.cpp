using namespace std;

#include "Crypto_u.h"
#include <fstream>
#include "../Ocalls/Ocall_file.h"


void AES256Encrypt(const uint8_t* plaintext, size_t plaintext_size, const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag) {

    EVP_CIPHER_CTX* ctx;
    int len = 0, ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("creating a new ctx failed.\n");
        return;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv, 1) != 1) {
        printf("AES encrypt initialization failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_size) != 1) {
        printf("failed to encrypt the data.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (EVP_CipherFinal_ex(ctx, tag, &len) != 1) {
        printf("failed to finalizing in encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        printf("authentication tag setting failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
}

RSA* GenerateRSAKeyPair(const BIGNUM** modulus, const BIGNUM** publicExponent) {
    
    int ret = 0;
    BIGNUM *bne = BN_new();

    ret = BN_set_word(bne,RSA_F4);
    if(ret != 1){
        BN_free(bne);
        printf("failed to set public exponent.\n");
        return nullptr;
    }
    
    RSA* rsa = RSA_new();
    if (!rsa) {
        printf("Failed to create an RSA structure.\n");
        return nullptr;
    }

    // Generate RSA key pair
    if (RSA_generate_key_ex(rsa, 2048, bne, nullptr) != 1) {
        printf("Failed to generate an RSA key pair.\n");
        RSA_free(rsa);
        return nullptr;
    }

    RSA_get0_key(rsa, modulus, publicExponent, nullptr);

    return rsa;
}
  
bool RSADecrypt(RSA* rsa_private_key, const unsigned char* encrypted_data, int encrypted_len, unsigned char** decrypted_data, int* decrypted_len) {
    
    *decrypted_data = new unsigned char[RSA_size(rsa_private_key)];

    *decrypted_len = RSA_private_decrypt(encrypted_len, encrypted_data, *decrypted_data, rsa_private_key, RSA_PKCS1_OAEP_PADDING);
    if (*decrypted_len == -1) {
        printf("RSA decryption with private key failed.\n");
        delete[] *decrypted_data;
        return false;
    }
    return true;
}