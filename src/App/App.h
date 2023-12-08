#ifndef APP_H
#define APP_H
 
#include <map>
#include <vector>
#include <cstring>

#include "Enclave_u.h"
#include "../common/utils.h"

  
#define ENCLAVE_SEAL_NAME "enclave_seal.signed.so"
#define BREACHED_PASSWORDS_FILE "BreachedPassword_Hashes.txt"
#define USER_PASSWORDS_FILE "UserPassword_Hashes.txt"
#define TEST_USER_PRIVATE_KEY "user_private_key.pem"
#define USERS_ID_FILE "Test/users_id.txt"

extern int g_user_id;


#endif