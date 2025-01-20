#include"encryption_data.hpp"

  std::string SM::generate_salt(int length = 16)
  {
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

  std::string SM::sm3_hash(const std::string& password, const std::string& salt)
  {
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
  };

  void SM::encrypt_with_cipher( Encrypted_elements *in, const EVP_CIPHER *cipher)
  {
    unsigned char *out_buf = NULL;
    int out_len;
    int out_padding_len;
    EVP_CIPHER_CTX *ctx;
 
    ctx = EVP_CIPHER_CTX_new();
    //key是密钥 iv是初始化向量 （在ecb模式中没有）
    EVP_EncryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);
    
    //>>4相当于 /16 计算有多少个完整的块 +1表示补全剩余数据 <<4 相当于*16 算出完整的字节数
    out_buf = (unsigned char *) malloc(((in->in_data_len>>4)+1) << 4 );
    out_len = 0;
    //当输入的不是整数块数时，会进行填充然后加密，填充的数据就是通过这个函数加密的
    EVP_EncryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len);
    if (1)
    {
        printf("Debug: out_len=%d\n", out_len);
    }
 
    out_padding_len = 0;
    EVP_EncryptFinal_ex(ctx, out_buf+out_len, &out_padding_len);
    if (1)
    {
        printf("Debug: out_padding_len=%d\n", out_padding_len);
    }
 
    EVP_CIPHER_CTX_free(ctx);
    if (1)
    {
        int i;
        int len;
        len = out_len + out_padding_len;
       for(int i=0;i<len;i++)
       {
        in->in_data[i]=out_buf[i];
       }
        in->in_data_len=len;
        for (i=0; i<len; i++)
        {
            printf("%02x ", in->in_data[i]);
        }
        printf("\n");
    }
 
    if (out_buf)
    {
        free(out_buf);
        out_buf = NULL;
    }
  }
  void SM::decrypt_with_cipher(const Encrypted_elements *in, const EVP_CIPHER *cipher)
  {
     unsigned char *out_buf = NULL;  
    int out_len;  
    int out_padding_len;  
    EVP_CIPHER_CTX *ctx;  

    ctx = EVP_CIPHER_CTX_new();  
    EVP_DecryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);  
    out_buf = (unsigned char *) malloc((in->in_data_len) ); // 分配足够的内存以存储解密数据  
    out_len = 0;  

    // 解密操作  
    if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len)) { 
        
        ERR_print_errors_fp(stderr); // 打印错误信息  
        free(out_buf);  
        EVP_CIPHER_CTX_free(ctx);  
        return;  
    }  
    
     printf("de1 = %d\n",out_len);
    out_padding_len = 0;  
    if (!EVP_DecryptFinal_ex(ctx, out_buf + out_len, &out_padding_len)) {  
         printf("de2 = %d\n",out_padding_len); 
        ERR_print_errors_fp(stderr); // 打印错误信息  
        free(out_buf);  
        EVP_CIPHER_CTX_free(ctx);  
        return;  
    }  

    EVP_CIPHER_CTX_free(ctx);  

    // 输出解密结果  
    int len = out_len + out_padding_len;  
    printf("Decrypted data (hex): ");  
    for (int i = 0; i < len; i++) {  
        printf("%02x ", out_buf[i]);  
    }  
    printf("\n");  

    free(out_buf);  
  }

  
  SM& SM::getInstance()
  {
    static SM instance;
    return instance;
  }