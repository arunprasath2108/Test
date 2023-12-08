#include "PasswordManager.h"

void DeserializeUserPasswords(uint8_t* passwords_arr, size_t arr_len) {

    std::string password;

    for(size_t i=0; i<= arr_len; i++) {
        if(passwords_arr[i] == '-') {
            g_userPasswords.insert(password);
            ++i;
            password.clear();
        }
        password += passwords_arr[i];        
    }
    g_userPasswords.insert(password);
}

void EcallGetUserPasswords(uint8_t* enc_passwords, size_t enc_pass_len, uint8_t* iv, size_t iv_len, uint8_t* tag, size_t tag_len) {

    size_t decrypted_len = enc_pass_len;
    uint8_t* decrypted_text = (uint8_t*)malloc(decrypted_len);
    decrypted_text = DecryptCipher(enc_passwords,enc_pass_len, iv, tag);
    if(decrypted_text == nullptr) {
        return;
    }

    //deserialize the byte arr into map
    DeserializeUserPasswords(decrypted_text, decrypted_len);
    free(decrypted_text);
}
 
std::tuple<std::string, std::string> SplitHash(const char* password) {
    std::string prefix = "";
    std::string suffix = "";
    for(size_t i=0; i< strlen(password); i++) {
        if(i < 5) {
            prefix += password[i];
        } else {
            suffix += password[i];
        }
    }
    return std::make_tuple(prefix, suffix);
} 

void GetBreachedPasswords(std::string hash_prefix) {
    
    char* untrusted_str;
    size_t len;
    int isResponseOK = 0;
    OcallGetAPIResponse(&isResponseOK, hash_prefix.c_str(), &untrusted_str, &len);
    if(isResponseOK == 0) {
        OcallPrintError("can't fetch breached passwords.");
        return;
    }
    char *hashes = new char[len]; 
    memcpy(hashes, untrusted_str, len);

    std::istringstream iss((std::string)hashes);

    while (iss) {
        std::string line;
        std::getline(iss, line);
        std::size_t pos = line.find(':');

        if (pos != std::string::npos) {
            std::string hash = line.substr(0, pos);
            g_breachedPasswords.insert(hash);
        }
    }

    delete[] hashes;
}

void CheckBreachedPasswords(stringSet userPasswords) {
    g_result_map.clear();
    g_breachedPasswords.clear();

    for (const std::string& password : userPasswords) {
    
        std::tuple<std::string, std::string> hash_split = SplitHash(password.c_str());
        std::string prefix_hash = std::get<0>(hash_split);
        std::string suffix_hash = std::get<1>(hash_split);
 
        GetBreachedPasswords(prefix_hash);
        bool isBreached = g_breachedPasswords.find(suffix_hash) != g_breachedPasswords.end();
        if(isBreached) {
            g_result_map[password] = "IsBreached";
        }
        g_breachedPasswords.clear();
    }

}
 
void DeserializeIntoMap(const char* serializedData) {
     
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

//convert char_array into public key components(mod, exp)
std::tuple<std::string, std::string> Convert(const char* str) {
    
    std::string modulus;
    std::string exponent;

    for(size_t i=0; i<strlen(str); i++) {
        if(str[i] == '|'){
            i+=1;
            for(size_t j=i; j!=strlen(str); j++) {
                exponent+=str[j];
            }
            i = strlen(str);
        }
        modulus+=str[i];
    }

    std::tuple<std::string, std::string> publicKey(modulus, exponent);
    return publicKey;
}

RSA* UnsealAndGetPublicKey(long long user_id) {

    size_t sealed_size;
    OcallGetFileSize(&sealed_size, SEALED_FILE_NAME);

    uint8_t* sealed_data = GetSealedFileContent(SEALED_FILE_NAME);
    if(sealed_data == nullptr) {
        free(sealed_data);
        OcallPrintError("sealed file content is null.");
        return nullptr;
    }

    uint32_t plaintext_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_data);
    uint8_t *unsealed_data = (uint8_t *)malloc(plaintext_size);
    if( plaintext_size == UINT32_MAX || unsealed_data == nullptr ) {
        free(unsealed_data);
        OcallPrintError("memory allocation failed for unsealed data.");
        return nullptr;
    }

    UnsealData(sealed_data, unsealed_data, plaintext_size);
    std::string unsealed_text(reinterpret_cast<char*>(unsealed_data), plaintext_size);
    std::string id_str = std::to_string(user_id);
    DeserializeIntoMap(unsealed_text.c_str());

    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    bool isUserPresent = false;

    for(auto it : g_users_map){

        if(it.first.c_str() == id_str) {
            isUserPresent = true;
            std::tuple<std::string, std::string> pubKeyComp = Convert(it.second.c_str());
            const char* modulus = std::get<0>(pubKeyComp).c_str();
            const char* exponent = std::get<1>(pubKeyComp).c_str();
            BN_hex2bn(&n, modulus);
            BN_hex2bn(&e, exponent);
        }
    }

    if( !isUserPresent) {
        std::string error_message = "No User present with ID : " + id_str;
        OcallPrintError(error_message.c_str());
        return nullptr;
    }

    RSA* publicKey = RSA_new();
    RSA_set0_key(publicKey, n, e, nullptr);
    if( !publicKey ) {
        OcallPrintError("can't set user's public key using mod & exp.");
        return nullptr;
    }

    free(sealed_data);
    free(unsealed_data);

    return publicKey;
}
  
void EncryptAndSendResult(long long user_id) {

    const char* serializedData = SerializeMap(g_result_map);
    uint8_t* plaintext = (uint8_t*)serializedData;
    int ciphertext_len = strlen((char*)plaintext);
    uint8_t* encryptedResult = (uint8_t*)malloc(ciphertext_len);
 
    RSA* publicKey = UnsealAndGetPublicKey(user_id);
    if( !publicKey ) { return; }
 
    int isEncrypted = RSAEncrypt(publicKey, (uint8_t*)serializedData, strlen((char*)serializedData), &encryptedResult, &ciphertext_len);
    if(!isEncrypted) {
        OcallPrintError("failed to encrypt Results.");
        return;
    }

    OcallSendResult(encryptedResult, ciphertext_len);
    RSA_free(publicKey);
    free(encryptedResult);
    
}
 
void EcallComparePasswords(long long user_id) {

    CheckBreachedPasswords(g_userPasswords);

    if( g_result_map.empty() ) {
        OcallPrintError("no breached password in user passwords.");
        return;
    }

    EncryptAndSendResult(user_id);

}
