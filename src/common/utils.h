#ifndef COM_UTIL_H
#define COM_UTIL


#define SEALED_FILE_NAME "sealed_file.txt"
#define AES_KEY_FILE_NAME "AES_secret_key.txt"

#include<iostream>

const int n_len = 256, e_len = 3;
 
struct UserData {
    long long int user_id;
    uint8_t e_buf[e_len];
    uint8_t n_buf[n_len];
};




#endif