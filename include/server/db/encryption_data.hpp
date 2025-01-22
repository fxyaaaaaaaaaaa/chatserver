#ifndef SM_ENCRYPTION
#define SM_ENCRYPTION
#include<iostream>
#include <iomanip>
#include<string>
#include <openssl/rand.h>  
#include<openssl/evp.h>
#include<string.h>
#include "openssl/err.h"
#define SM3_DIGEST_LENGTH 32
typedef struct {
    unsigned char *in_data;
    size_t in_data_len;
    const unsigned char *in_ivec;
    const unsigned char *in_key;
    size_t in_key_len;
} Encrypted_elements;
class SM
{
    public:
    std::string generate_salt(int length);
    std::string sm3_hash(const std::string& password, const std::string& salt);
    //SM4对称加密
    void encrypt_with_cipher( Encrypted_elements *in, const EVP_CIPHER *cipher);
    void decrypt_with_cipher(const Encrypted_elements *in, const EVP_CIPHER *cipher);
    static SM& getInstance();
    private:
    SM(){};
    SM(SM&)=delete;
    SM& operator=(const SM&)=delete;
};
#endif