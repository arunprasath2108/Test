#include "App.h"
#include "sgx_urts.h"
#include "Ocalls/Ocall_file.h"
#include "CryptoUntrusted/Crypto_u.h"
#include <ctime>

static std::vector<std::string> temp_arr;
const char** B_P_array = nullptr;
const char** U_P_array = nullptr;

UserData* test_user;
sgx_enclave_id_t eid;
int g_user_id = 0;

int GenerateRandomNumber() {
    
    std::srand(static_cast<unsigned int>(std::time(0)));
    int random_number = std::rand() % 100000;
    return random_number;
}

static sgx_status_t InitializeEnclave(const char* enclave_path)
{
    sgx_status_t ret;
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if ( ret != SGX_SUCCESS ) {
        return ret;
    }
    return SGX_SUCCESS;
}

uint8_t* SerializePasswords(const char* passwords[], size_t password_count) {
    std::string serializedData;

    for (size_t i = 0; i < password_count; ++i) {
        serializedData += passwords[i];

        if (i < password_count - 1) {
            serializedData += "-";
        }
    }

    uint8_t* buffer = new uint8_t[serializedData.size() + 1];
    std::memcpy(buffer, serializedData.c_str(), serializedData.size() + 1);

    return buffer;
}

uint8_t* GenerateIV() {

    uint8_t* iv = (uint8_t*)malloc(EVP_MAX_IV_LENGTH);
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        printf("failed to generate IV.\n");
        return nullptr;
    }
    return iv;
}

bool SendUserdata() {

    int plaintext_size = sizeof(UserData);
    uint8_t* plaintext = new unsigned char[plaintext_size];
    plaintext = (uint8_t*)test_user;
    
    size_t ciphertext_size = plaintext_size;

    uint8_t* key = GetAESKeyFromFile(AES_KEY_FILE_NAME);
    if(key == nullptr) {
        free(plaintext);
        printf("failed to load key from %s\n", AES_KEY_FILE_NAME);
        return false;
    }

    uint8_t ciphertext[ciphertext_size];
    uint8_t* iv = GenerateIV();
    if(iv == nullptr){
        free(key);
        delete[] plaintext;
        return false;
    }
    uint8_t* tag = (uint8_t*)malloc(16);
  
    AES256Encrypt(plaintext, plaintext_size, key, iv, ciphertext, tag);
    
    sgx_status_t seal_status = EcallSealData(eid, ciphertext, ciphertext_size, iv, strlen((char*)iv), tag, strlen((char*)tag));
    if( seal_status != SGX_SUCCESS ) { return false; }

    free(key);
    free(tag);
    free(iv);
    delete[] plaintext;

    return true;
}

void GetBreachedPasswords(const char* FILE_NAME) {
    //check - xml file for heap size to send more data
    temp_arr.clear();
    temp_arr = ReadFileLines(FILE_NAME);
    size_t len = temp_arr.size();
    B_P_array = new const char*[len];
    for(size_t i=0; i<len; i++) {
        B_P_array[i] = temp_arr[i].c_str();
    }

}

void GetUserPasswords(const char* FILE_NAME) {
    temp_arr.clear();
    temp_arr = ReadFileLines(FILE_NAME);
    size_t len = temp_arr.size();
    U_P_array = new const char*[len];
    for(size_t i=0; i<len; i++) {
        U_P_array[i] = temp_arr[i].c_str();
    }
}

bool SendBreachedPasswords() {

    GetBreachedPasswords(BREACHED_PASSWORDS_FILE);

    sgx_status_t sgx_sts = EcallGetBreachedPasswords(eid, B_P_array, temp_arr.size());
    if( sgx_sts != SGX_SUCCESS ) { 
        return false; 
    }

    delete[] B_P_array;
    return true;
}

bool SendUserPasswords() {

    sgx_status_t sgx_status;

    GetUserPasswords(USER_PASSWORDS_FILE);
    
    uint8_t* serialized_passwords = SerializePasswords(U_P_array, temp_arr.size());
    size_t plaintext_size = strlen((char*)serialized_passwords) + 1;        
    size_t ciphertext_size = plaintext_size;
    uint8_t* key = GetAESKeyFromFile(AES_KEY_FILE_NAME);
    if(key == nullptr) {
        printf("failed to load key from %s\n",AES_KEY_FILE_NAME);
        return false;
    }

    uint8_t ciphertext[ciphertext_size];
    uint8_t* iv = GenerateIV();
    if(iv == nullptr){
        return false;
    }
    uint8_t* tag = (uint8_t*)malloc(16);
    
    AES256Encrypt(serialized_passwords, plaintext_size, key, iv, ciphertext, tag);
    
    sgx_status = EcallGetUserPasswords(eid, ciphertext, ciphertext_size, iv, strlen((char*)iv), tag, strlen((char*)tag));
    if( sgx_status != SGX_SUCCESS ) { 
        return false;
    }

    delete[] U_P_array;
    delete[] serialized_passwords;
    free(key);
    free(tag);
    free(iv);
    return true;
}

bool CheckBreachedPasswords(long long user_id) {

    // NOTE: user passwords are already loaded into enclave memory.

    sgx_status_t sgx_status = EcallComparePasswords(eid, user_id);
    if( sgx_status != SGX_SUCCESS ) { return false; }
    
    return true;
}

void ViewOptions() {

    printf("\n ----- Breach Detection -----\n");
    
    printf("[1] add user.\n");
    printf("[2] breach detect for existing user.\n");
    printf("[3] exit.\n\n");

}

int GetUserInput() {

    int input;
    while(true) {
        printf("choose an option : ");
        std::cin >> input;
        if(input > 0 && input < 4) {
            return input;
        }
        else {
            OcallPrintError("input mismatch.");
            std::cin.clear();
            std::cin.ignore(1000, '\n');
        }      
    }
}

bool IsUserExists(int user_id) {

    std::string uid = std::to_string(user_id);

    std::vector<std::string> existing_users = ReadFileLines(USERS_ID_FILE);

    for( int i=0; i<existing_users.size(); i++ ) {
        if(existing_users[i] == uid) {
            return true;
        }
    }
    return false;
}

int GetUserIDForComparison() {

    while(true) {
        printf("enter user id for breach test : ");
        std::cin >> g_user_id;
        if(g_user_id > 0 && g_user_id <= 99999) {
            return g_user_id;
        }
        else {
            OcallPrintError("input mismatch.");
            std::cin.clear();
            std::cin.ignore(1000, '\n');
        }      
    }
}

int GetNewUserID() {

    int input;
    while(true) {
        
        printf("Enter user id between 1 - 99999 : ");
        std::cin >> input;
        if(input > 0 && input <= 99999) {

            if( OcallIsFileExist(USERS_ID_FILE) == 1) {
                if(IsUserExists(input) == false) {
                    return input;
                }
                else {
                    printf("user id %d already exists.\n", input);
                }
            }
            else {
                return input;
            }
        }
        else {
            OcallPrintError("user id is invalid.");
            std::cin.clear();
            std::cin.ignore(1000, '\n');
        }    

    }
}

void AddUser() {

    long long uid = GetNewUserID();

    //save user id
    if (!SaveUserID(USERS_ID_FILE, uid)) {
        printf("can't save user id to file.\n");
        return;
    }

    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA* rsa = GenerateRSAKeyPair(&n, &e);
    if (rsa == nullptr) {
        RSA_free(rsa);
        printf("failed to generate rsa keys.\n");
        return;
    }

    std::string uid_str = std::to_string(uid);
    std::string keys_file = "Test/keys/" + uid_str + "_key.pem";

    //save private key to file
    if (!SaveKeyToFile(keys_file.c_str(), rsa)) {
        RSA_free(rsa);
        printf("can't save key to file.\n");
        return;
    }

    test_user = new UserData;
    test_user->user_id = uid;
    BN_bn2bin(n, test_user->n_buf);
    BN_bn2bin(e, test_user->e_buf);

    printf("[SUCCESS] created a user with id : %lld\n", uid);

    if( SendUserdata() ) {
        printf("[SUCCESS] userdata sealed successfully.\n"); 
    }

    RSA_free(rsa);
}

void BreachDetection() {

    if(OcallIsFileExist(SEALED_FILE_NAME) == 0) {
        printf("sorry! no users are available.\n");
        return;
    }

    if(SendUserPasswords() == false) {
        printf("can't load user passwords inside the enclave memory.\n");
        return;
    }

    if(SendBreachedPasswords() == false) {
        printf("can't load breached passwords inside the enclave memory.\n");
        return;
    }

    g_user_id = GetUserIDForComparison();
    if( CheckBreachedPasswords(g_user_id) == false ) {
        printf("breach detection failed.\n"); 
    }

}

int main() {

    sgx_status_t sgx_status = InitializeEnclave(ENCLAVE_SEAL_NAME);
    if ( sgx_status != SGX_SUCCESS )
    {   
        printf("enclave initialization failed.\n");
        return 0;
    }

    ViewOptions();

    int usr_opt = GetUserInput();
    if(usr_opt == 1) 
    {
        AddUser();
    } 
    else if(usr_opt == 2) 
    {
        BreachDetection();
    } 
    else if(usr_opt == 3) 
    {
        printf("program terminated.\n");
    }
    else 
    {
        printf("invalid user input.\n");
    }

    return 0;

}
