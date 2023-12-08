#ifndef ENCLAVE_H
#define ENCLAVE_H


#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "string.h"
#include "PasswordManager/PasswordManager.h"
#include "Crypto/Crypto.h"
#include <unordered_map>
#include "../common/utils.h"

//global user's map
static std::unordered_map<std::string, std::string> g_users_map;
  
uint8_t* GetSealedFileContent(const char* FILE_NAME);
void UnsealData(uint8_t* sealed_data, uint8_t* unsealed_data, uint32_t plaintext_size);
uint8_t* DecryptCipher(uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, uint8_t* tag);
const char* SerializeMap(const std::unordered_map<std::string, std::string>& local_map);

#endif


