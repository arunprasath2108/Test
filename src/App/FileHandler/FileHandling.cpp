#include "FileHandling.h"

//save the contents into file
bool SaveFile(const uint8_t* sealed_data, const size_t sealed_size) {
    std::ofstream file(SEALED_FILE_NAME, std::ios_base::out);
    if( file.fail() ) {
        printf("failed to open the file %s\n",SEALED_FILE_NAME);
        return false;
    }

    file.write((const char*) sealed_data, sealed_size);
    file.close();
    return true;
}

//get the file contents
bool GetFileContent(const char* FILE_NAME, uint8_t* data, const size_t data_size) {
    std::ifstream file(FILE_NAME, std::ios_base::in);
    if( file.fail() ) {
        printf("failed to open the file %s\n", FILE_NAME);
        return false;
    }

    file.read((char*) data, data_size);
    file.close();
    return true;
}

//read the file size
size_t GetFileSize(const char* FILE_NAME) {
    std::ifstream file(FILE_NAME, std::ios::in | std::ios::binary);
    if ( file.fail() ) {
        printf("failed to open the file %s\n",FILE_NAME);
        return 0;
    }
     
    file.seekg(0, std::ios::end);
    size_t size = (size_t)file.tellg();
    file.close();
    return size;
}

uint8_t* GetAESKeyFromFile(const char* FILE_NAME) {

    size_t key_size = GetFileSize(FILE_NAME);
    uint8_t* key = (uint8_t*)malloc(key_size);
    bool isKey = GetFileContent(FILE_NAME, key, key_size);
    if( !isKey ) {
        free(key);
        return nullptr;
    } 
    
    return key;
}

std::vector<std::string> ReadFileLines(const std::string& FILE_NAME) {
  
  std::vector<std::string> lines;

  std::ifstream file(FILE_NAME);
  if (!file.is_open()) {
    printf("failed to open the file.\n");
  }

  std::string line;
  while (std::getline(file, line)) {
    lines.push_back(line);
  }

  file.close();
  return lines;
}

bool SaveKeyToFile(const char* FILE_NAME, RSA* key) {
    FILE* file = fopen(FILE_NAME, "w");
    if (!file) {
        printf("failed to opening file for writing %s\n",FILE_NAME);
        return false;
    }

    int success;
    success = PEM_write_RSAPrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr);

    fclose(file);

    if (success != 1) {
        return false;
    }
    return true;
}

bool SaveUserID(const char* FILE_NAME, long long user_id) {
    
    std::ofstream file(FILE_NAME, std::ios_base::app);
    if( file.fail() ) {
        printf("failed to open the file %s\n", FILE_NAME);
        return false;
    }

    file << user_id << std::endl;
    file.close();
    return true;
}

RSA* LoadRSAKeyFromFile(const char* FILE_NAME, bool isPrivateKey) {
    FILE* file = fopen(FILE_NAME, "r");
    if (!file) {
        printf("failed to opening file for reading %s\n",FILE_NAME);
        return nullptr;
    }

    RSA* key = nullptr;
    if (isPrivateKey) {
        key = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    } else {
        key = PEM_read_RSAPublicKey(file, nullptr, nullptr, nullptr);
    }
 
    fclose(file);

    if (!key) {
        free(key);
        return nullptr;
    }

    return key;
}