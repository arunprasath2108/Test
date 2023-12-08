#include "Ocall_file.h"

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

void PrintDecryptedData(const std::string& decryptedStr) {
    std::istringstream iss(decryptedStr);
    std::string pair;

    while (std::getline(iss, pair, '~')) {
        size_t dashPos = pair.find('-');
        if (dashPos != std::string::npos) {
            std::string hash = pair.substr(0, dashPos);
            std::string hash_status = pair.substr(dashPos + 1);
            std::cout << hash << " : " << hash_status << std::endl;
        }
    }
}

void OcallSendResult(uint8_t*ciphertext, size_t cipher_len) {

    std::string uid = std::to_string(g_user_id);
    std::string key_file = "Test/Keys/" + uid + "_key.pem";

    RSA* privateKey = LoadRSAKeyFromFile(key_file.c_str(), true);
    if (!privateKey) {
        RSA_free(privateKey);
        printf("failed to load the private key from file %s\n.", key_file.c_str());
        return;
    }

    unsigned char* decrypted_data = nullptr;
    int decrypted_len = 0;
    if (RSADecrypt(privateKey, ciphertext, (int)cipher_len, &decrypted_data, &decrypted_len)) {
        std::cout << "\nBreached Passwords :\n-----------------------------------------------------\n";
        std::string decryptedStr =  std::string(reinterpret_cast<char*>(decrypted_data), decrypted_len);
        PrintDecryptedData(decryptedStr);
    }

    free(decrypted_data);
    RSA_free(privateKey);
}
 
int OcallGetAPIResponse(const char* prefix_hash, char* str[], size_t* length) {

    std::string URL = API_URL + prefix_hash;
    std::string response = FetchData(URL);
    if(response.empty()) {
        return 0;
    }

    *length = response.length();
    *str = new char[*length + 1];
    std::strcpy(*str, response.c_str());
    return 1;
}   
