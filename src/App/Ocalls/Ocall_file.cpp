#include "Ocall_file.h"

#include "../CryptoUntrusted/Crypto_u.h"

//print string
void OcallPrintError(const char* error_message) {
    printf("[ERROR] %s\n", error_message);
}
  
void OcallSaveFile(uint8_t* sealed_data, size_t sealed_size) {
    bool isFileSaved = SaveFile(sealed_data, sealed_size);
    if( !isFileSaved ) {
        printf("failed in writing to the file.\n");
    }
}

int OcallIsFileExist(const char* FILE_NAME) {
    std::ifstream file(FILE_NAME, std::ios::in | std::ios::binary);
    if ( file.fail() ) { return 0; }
    file.close();
    return 1;
}

size_t OcallGetFileSize(const char* FILE_NAME) {
    return GetFileSize(FILE_NAME);
}

void LoadFile( const char* FILE_NAME, uint8_t* sealed_data, size_t sealed_size) {
    bool isFileLoaded = GetFileContent(FILE_NAME, sealed_data, sealed_size);
    if( !isFileLoaded )
    printf("unable to load the file %s\n.", FILE_NAME);
}

void OcallSendResult(uint8_t*ciphertext, size_t cipher_len) {
    
    std::string uid_str = std::to_string(g_user_id);
    std::string keys_file = "Test/keys/" + uid_str + "_key.pem";

    RSA* privateKey = LoadRSAKeyFromFile(keys_file.c_str(), true);
    if (!privateKey) {
        RSA_free(privateKey);
        printf("failed to load the private key from file %s\n.", TEST_USER_PRIVATE_KEY);
        return;
    }

    unsigned char* decrypted_data = nullptr;
    int decrypted_len = 0;
    if (RSADecrypt(privateKey, ciphertext, (int)cipher_len, &decrypted_data, &decrypted_len)) {
        std::cout << "Breached Passwords :  \n" << std::string(reinterpret_cast<char*>(decrypted_data), decrypted_len) << std::endl;
    }

    free(decrypted_data);
    RSA_free(privateKey);
}

// void printCipher(uint8_t* ciphertext, size_t cipher_len){
//     Ocall_PrintCipherText(ciphertext, cipher_len);
// }

// void ocall_print_uc(uint8_t* str, size_t len){
//     printf("unsigned char size : %li ", len);
//     printf("%s", str);
// }

// void Ocall_PrintCipherText(uint8_t* ciphertext, int ciphertext_len) {
    
//     for (size_t i = 0; i < ciphertext_len; ++i) {
//         printf("%02X ", ciphertext[i]);
//     } 
   
//     std::cout << std::endl;
// }

// void ocall_print_int(size_t num) {
//     std::cout << "num : " << num << "\n";
// }
