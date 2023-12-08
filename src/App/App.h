#ifndef APP_H
#define APP_H
 
#include <map>
#include <vector>
#include <cstring>
#include <ctime>

#include "Enclave_u.h"
#include "sgx_urts.h"

#include "../common/utils.h"
#include "Ocalls/Ocall_file.h"
#include "CryptoUntrusted/Crypto_u.h"

  
#define ENCLAVE_SEAL_NAME "enclave_seal.signed.so"
#define USER_PASSWORDS_FILE "UserPassword_Hashes.txt"
#define USERS_ID_FILE "Test/users_id.txt"

extern int g_user_id;


#endif