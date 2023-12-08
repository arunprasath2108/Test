#ifndef FILE_HANDLING_H
#define FILE_HANDLING_H

#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "../App.h"
    
bool SaveFile(const uint8_t* sealed_data, const size_t sealed_size);
bool GetFileContent(const char* FILE_NAME, uint8_t* sealed_data, size_t sealed_size);
size_t GetFileSize(const char* FILE_NAME);
uint8_t* GetAESKeyFromFile(const char* FILE_NAME);
std::vector<std::string> ReadFileLines(const std::string& FILE_NAME);
bool SaveKeyToFile(const char* FILE_NAME, RSA* key);
RSA* LoadRSAKeyFromFile(const char* FILE_NAME, bool isPrivateKey);
bool SaveUserID(const char* FILE_NAME, long long user_id);


#endif