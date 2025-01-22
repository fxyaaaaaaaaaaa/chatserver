#ifndef GMSSL_CLIENT
#define GMSSL_CLIENT
#include <fstream>   // for std::ifstream  
#include <random>    // for std::random_device
#include "gmssl/sm2.h"
#include "gmssl/sm3.h"
#include "gmssl/sm4.h"
#include "gmssl/rand.h"
#include"gmssl/x509.h"
#include "gmssl/x509_cer.h"
#include "gmssl/x509_req.h"
#include <arpa/inet.h> // For sockets on UNIX/Linux  
#include <unistd.h> 
#include<string.h>
#include<string>// For close()
using namespace std;
#define SM2_MIN_XYHASH_SIZE			(32 * 3)
#define CA_PATH "../certs/signcert.pem"
#define SM2_PRIVATE_PATH "../certs/signkey.pem"
// typedef unsigned char UCHAR;


 
#pragma pack(1)
#define REQ_CERTI 1
#define RSP_CERTI 2
#define REQ_CHANGE_IV 3
#define RSP_CHANGE_IV 4
#define REQ_ENCODE_TEST 5
#define RSP_ENCODE_TEST 6
typedef unsigned char UCHAR;
typedef unsigned int UINT;
typedef unsigned short USHORT;
static bool flag=false;
typedef int BOOL;

class gmssl_helpe
{
public:
	size_t certification_len;
	UCHAR certification[1024];
	UCHAR sm4_key[16];
	UCHAR s_sm4_iv[16];
	SM2_KEY m_ca_1_key;		 // CA颁发的密钥对 包含公钥和私钥
	SM2_KEY m_server_sm2key; // 服务端密钥 仅包含公钥
	UCHAR r1[8];
	UCHAR R2[8];
	int sock;
	static gmssl_helpe &get_instance();
	void generate_random_numbers(UCHAR *out_data, int type);
	bool load_certification(std::string fullpath);
	// void sign_message(unsigned char *message, unsigned char *signature);
	bool load_private_key(const std::string &pem_file);
	BOOL wa_load_pub_key(const char *sign_cert_path, void *out_public_key);

	// sm2 私钥解密

	int sm2_slice_decrypt(SM2_KEY *sm2key, const uint8_t *in_data, const int in_len, uint8_t *out_data, size_t *out_len);
	int sm2_nop2der(SM2_CIPHERTEXT *out_der, const uint8_t *in_data, const size_t in_len, int type  );
	bool verify_r2(UCHAR *r2);
	// sm2加密der转04非压缩格式;type默认为1,c1c3c2格式;0则为c1c2c3格式
	int sm2_der2nop(const SM2_CIPHERTEXT *sm2der, uint8_t *out_data, size_t *out_len, int type );
	bool gm_sm2_encrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t *out_len);

	// 签名

	size_t wa_sm2_sign_data(void *pri_key, const uint8_t *in_data, const size_t in_len, uint8_t *out_buff);

	// 将ASN.1格式数据转换为原始数据(R,S),原始数据长度为64字节固定 ,签名后的数据是der格式通过此转换为64字节原数据
	BOOL wa_asn1_to_raw(const uint8_t *in_data, const size_t in_len, uint8_t *out_buff);
	// 将原始数据(R,S)转换为ASN.1格式数据
	BOOL gm_raw_to_asn1(const uint8_t *in_data, uint8_t *out_buff, size_t *out_len);

	// sm4加密
	bool gm_sm4_encrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t &out_len);
	bool gm_sm4_decrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t *out_len);

private:
	gmssl_helpe()
	{
		certification_len = 0;
		memset(certification, 0, sizeof certification);
		memset(&m_ca_1_key, 0, sizeof m_ca_1_key);
		memset(r1, 0, sizeof r1);
		memset(R2, 0, sizeof R2);
		memset(sm4_key, 0, sizeof sm4_key);
	};
	gmssl_helpe(gmssl_helpe &) = delete;
	gmssl_helpe &operator=(gmssl_helpe &) = delete;
};




#endif
