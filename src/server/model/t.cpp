#include<iostream>
#include <iomanip>
#include<string>
#include <openssl/rand.h>  
#include<openssl/evp.h>
#include<string.h>
#define SM3_DIGEST_LENGTH 32
using namespace std;
//生成盐值
std::string generate_salt(int length = 16) {  
    unsigned char salt[length];
    //生成随机字节 ,保存在salt中
    if (RAND_bytes(salt, sizeof(salt)) != 1) {  
        throw std::runtime_error("Error generating salt.");  
    }  
    std::stringstream ss;  
    for (int i = 0; i < length; ++i) {  
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];  
    }  
    return ss.str();  
} 

std::string sm3_hash(const std::string& password, const std::string& salt) {  
    std::string to_hash = password + salt;  
    unsigned char hash[SM3_DIGEST_LENGTH]; 

    //unsigned char sm3_value[EVP_MAX_MD_SIZE];   //保存输出的摘要值的数组
    unsigned int sm3_len, i;
    EVP_MD_CTX *sm3ctx;                         //EVP消息摘要结构体
    sm3ctx = EVP_MD_CTX_new();//调用函数初始化             //待计算摘要的消息1
    //char msg2[] = "hzx";              //待计算摘要的消息2
     
    EVP_MD_CTX_init(sm3ctx);                    //初始化摘要结构体
    EVP_DigestInit_ex(sm3ctx, EVP_sm3(), NULL); //设置摘要算法和密码算法引擎，这里密码算法使用sm3，算法引擎使用OpenSSL默认引擎即软算法
    EVP_DigestUpdate(sm3ctx, to_hash.c_str(), strlen(to_hash.c_str()));//调用摘要UpDate计算msg1的摘要
    //EVP_DigestUpdate(sm3ctx, msg2, strlen(msg2));//调用摘要UpDate计算msg2的摘要 
    EVP_DigestFinal_ex(sm3ctx, hash, &sm3_len);//摘要结束，输出摘要值   
    EVP_MD_CTX_reset(sm3ctx);                       //释放内存
    
   

    std::stringstream ss;  
    for (int i = 0; i < sm3_len; ++i) {  
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];  
    }  
    return ss.str();  
}  
int main()
{
    string salt=generate_salt(16);
    string password="123";
    string hash=sm3_hash(password,salt);
    cout<<hash;
    return 0;
}