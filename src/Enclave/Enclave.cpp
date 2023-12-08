#include "Enclave.h"
#include <iostream>
#include <cstring>
 

uint8_t* GetSealedFileContent(const char* FILE_NAME) {

    // Read the sealed blob from the file
    size_t sealed_size;
    OcallGetFileSize(&sealed_size, FILE_NAME);
    if( sealed_size == 0 || sealed_size == (size_t)-1 ) 
    {   
        OcallPrintError("failed in getting sealed file size.");
        return nullptr; 
    }

    uint8_t *sealed_data = (uint8_t *)malloc(sealed_size);
    if( sealed_data == nullptr )
    {
        OcallPrintError("memory allocation failed.");
        free(sealed_data);
        return nullptr;
    }
    if( LoadFile(FILE_NAME, sealed_data, sealed_size) != SGX_SUCCESS ) {
        OcallPrintError("failed to load the sealed file.");
        free(sealed_data);
        return nullptr;
    }

    return sealed_data;
}

void DeserializeMap(const char* serializedData) {
     
    std::string keyValueString;
    std::string key;
    std::string value;

    //seperate key, value pairs.
    for(size_t i=0; i<strlen(serializedData); i++) {
        
        if( serializedData[i] == '-' ) {

            key.append(keyValueString.c_str());
            keyValueString.clear();
        } 
        else if( serializedData[i] == '~' ) {

            value.append(keyValueString.c_str());
            keyValueString.clear();
        } 
        else {

            keyValueString += serializedData[i];
        }

        //add the key-value pair to the map
        if(key.size() != 0 && value.size() != 0) {
            g_users_map[key] = value;
            key.clear();
            value.clear();
            keyValueString.clear();
        }
    }
}

void UnsealAndDeserializeIntoMap() {

    size_t sealed_size;
    OcallGetFileSize(&sealed_size, SEALED_FILE_NAME);
    uint8_t* sealed_data = GetSealedFileContent(SEALED_FILE_NAME);
    if(sealed_data == nullptr) {
        free(sealed_data);
        OcallPrintError("sealed file content is null.\n");
        return; 
    }
    uint32_t plaintext_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    if(plaintext_size == UINT32_MAX) {
        OcallPrintError("encrypted data size is null.");
        return;
    }
    uint8_t *unsealed_data = (uint8_t *)malloc(plaintext_size);
    if(  unsealed_data == nullptr ) {
        free(unsealed_data);
        OcallPrintError("memory allocation failed for unsealing data.\n");
        return;
    }

    UnsealData(sealed_data, unsealed_data, plaintext_size);

    std::string unsealed_text(reinterpret_cast<char*>(unsealed_data), plaintext_size);
    DeserializeMap(unsealed_text.c_str());
    free(sealed_data);
    free(unsealed_data);
}

void UnsealData(uint8_t* sealed_data, uint8_t* unsealed_data, uint32_t plaintext_size) {

    sgx_status_t unseal_status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, unsealed_data, &plaintext_size);
    if(unseal_status != SGX_SUCCESS) {
        OcallPrintError("unsealing in enclave memory.\n");
    }
}

void SealAndSaveData(const char* serializedData) {

    sgx_status_t sealing_status;

    //calc sealed data size
    uint32_t sealed_size = sgx_calc_sealed_data_size(0, strlen(serializedData));
    if ( sealed_size < 0 ) {
        OcallPrintError("sealed data size calculation failed.\n");
    }

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if ( sealed_data == nullptr ) {
        free(sealed_data);
        OcallPrintError("memory allocation failed for sealed data.\n");
    }

    sealing_status = sgx_seal_data(0, NULL, strlen(serializedData), (const uint8_t*)serializedData, (uint32_t)sealed_size, (sgx_sealed_data_t*)sealed_data);
    if ( sealing_status != SGX_SUCCESS ) {
        free(sealed_data);
        OcallPrintError("sealing data failed inside enclave.\n");
    }

    //save the sealed content in file
    OcallSaveFile(sealed_data, sealed_size);
    free(sealed_data);
}

uint8_t* DecryptCipher(uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, uint8_t* tag) {

    uint8_t* key = GetSealedFileContent(AES_KEY_FILE_NAME);
    if(key == nullptr) {
        OcallPrintError("can't get key to decrypt.");
        return nullptr;
    }

    int tag_verification;
    size_t decrypted_len = cipher_len;
    uint8_t* decrypted_text = (uint8_t*)malloc(decrypted_len);
    int decrypted = AES256Decrypt(key, ciphertext, cipher_len, decrypted_text, iv, tag, &tag_verification);

    if( !decrypted ) {
        free(decrypted_text);
        free(ciphertext);
        return nullptr;
    }
    if ( !tag_verification) {
        free(decrypted_text);
        free(ciphertext);
        OcallPrintError("tag verification failed in AES decryption. Data may be tampered.");
        return nullptr;
    }

    free(key);

    return decrypted_text;
}

std::string GetKeyComponents(struct UserData* user) {

    BIGNUM* n = BN_bin2bn(user->n_buf, n_len, nullptr);
    BIGNUM* e = BN_bin2bn(user->e_buf, e_len, nullptr);

    char* mod_hex = BN_bn2hex(n);
    char* exp_hex = BN_bn2hex(e);
    char delimiter = '|';

    std::string modulus(mod_hex);
    std::string exponent(exp_hex);
    std::string key_comp = modulus + delimiter + exponent;

    BN_free(n);
    BN_free(e);

    return key_comp;  // output as : "modulus|exponent"
}

void EcallSealData(uint8_t* ciphertext, size_t cipher_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len) {
    
    std::string serializedData = "";
    size_t decrypted_len = cipher_len;
    uint8_t* decrypted_text = (uint8_t*)malloc(decrypted_len);

    decrypted_text = DecryptCipher(ciphertext, cipher_len, iv, tag);
    if(decrypted_text == nullptr) { return; }
    
    int is_file_present = 0;
    OcallIsFileExist(&is_file_present, SEALED_FILE_NAME);
    
    if(is_file_present) {
        //unseal the sealed data, deserialize into map for further data insertion.
        UnsealAndDeserializeIntoMap();
    } 
 
    UserData* user = new UserData;
    user = (UserData*)decrypted_text;

    std::string key_components = GetKeyComponents(user);
    std::string ID = std::to_string(user->user_id);
    g_users_map.insert(std::make_pair(ID, key_components));

    serializedData = SerializeMap(g_users_map);
    g_users_map.clear();
    SealAndSaveData(serializedData.c_str());

}   

const char* SerializeMap(const std::unordered_map<std::string, std::string>& local_map) {
 
    std::string serializedData;
    
    for (const auto& entry : local_map) {
        serializedData.append(entry.first.c_str());
        serializedData.append("-");     
        serializedData.append(entry.second.c_str());
        serializedData.append("~");     
    }
     
    return serializedData.c_str();
}