#include "Crypto.h"

 
int AES256Decrypt(uint8_t* key, uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, uint8_t* iv, uint8_t* tag, int* tag_verification) {

    EVP_CIPHER_CTX *ctx;
    int plain_len, len, ret = 1;


    if( !(ctx = EVP_CIPHER_CTX_new()) ){
        ret =  0;
        goto free_memory;
    }
 
    if( EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key,iv,0) != 1) {
        ret =  0;
        goto free_memory;
    }

    if( EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        ret =  0;
        goto free_memory;
    }

    if( EVP_CipherInit_ex(ctx, NULL, NULL, key,iv,0) != 1) {
        ret =  0;
        goto free_memory;
    }

    if( EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        ret =  0;
        goto free_memory;
    }

    plain_len = len;
    *tag_verification = EVP_CipherFinal_ex(ctx, plaintext, &len);

    return ret;

    free_memory:
     EVP_CIPHER_CTX_free(ctx);
     OcallPrintError("AES decryption inside enclave memory failed.");
     return ret;

}
       
bool RSAEncrypt(RSA* rsa_public_key, const unsigned char* plaintext, size_t plaintext_len, unsigned char** encrypted_data, int* encrypted_len) {
    
    *encrypted_data = new unsigned char[RSA_size(rsa_public_key)];

    *encrypted_len = RSA_public_encrypt((int)plaintext_len, plaintext, *encrypted_data, rsa_public_key, RSA_PKCS1_OAEP_PADDING);
    if (*encrypted_len == -1) {
        OcallPrintError("RSA encryption with public key failed.");
        delete[] *encrypted_data;
        return false;
    }
    
    return true;
}