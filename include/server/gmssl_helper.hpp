#ifndef __GMSSL_HELPER__HPP__
#define __GMSSL_HELPER__HPP__

#include "./gmssl/sm2.h"
#include "./gmssl/sm3.h"
#include "./gmssl/sm4.h"
#include "./gmssl/rand.h"
#include "./gmssl/x509_cer.h"
#include "./gmssl/x509_req.h"
#include"logger.h"

class gmssl_helper
{

#define SM2_MIN_XYHASH_SIZE			(32 * 3)


// CA中间证书,cacert.pem
const char* s_ca_cert_data = "-----BEGIN CERTIFICATE-----\n"
								"MIIB6DCCAY6gAwIBAgIMI4AwRGN9s+Noch7zMAoGCCqBHM9VAYN1MGYxCzAJBgNV\n"
								"BAYTAkNOMREwDwYDVQQIEwhaaGVqaWFuZzERMA8GA1UEBxMISGFuZ3pob3UxDzAN\n"
								"BgNVBAoTBmhvb2t3ZTEPMA0GA1UECxMGaG9va3dlMQ8wDQYDVQQDEwZST09UQ0Ew\n"
								"HhcNMjUwMTAzMDYxNTU0WhcNMjYwMTAzMDYxNTU0WjBiMQswCQYDVQQGEwJDTjER\n"
								"MA8GA1UECBMIWmhlamlhbmcxETAPBgNVBAcTCEhhbmd6aG91MQ8wDQYDVQQKEwZo\n"
								"b29rd2UxDzANBgNVBAsTBmhvb2t3ZTELMAkGA1UEAxMCQ0EwWTATBgcqhkjOPQIB\n"
								"BggqgRzPVQGCLQNCAATJS4wLmuSAsN/R4CN5ZhRCuxQ+6zimXVRLMAv1qVs2PBKN\n"
								"ou4p2Vm4fMcePC+mnIDY6208J+JkkhOum580NUYRoyYwJDAOBgNVHQ8BAf8EBAMC\n"
								"AgQwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqgRzPVQGDdQNIADBFAiEA4Za90VSC\n"
								"8aVtUnrZJGzCajGRZASO4pbLmuN0ltvHIq8CIHAXKHSZl2nXxWenSG76Mnu+pzQL\n"
								"riy4A+8VyBZvgA2U\n"
								"-----END CERTIFICATE-----\n";

public:
	gmssl_helper()
	{
		memset(&m_client_sm2key,0,sizeof(m_client_sm2key));
		memset(&m_local_sm2key,0,sizeof(m_local_sm2key));
		memset(&m_ca_cert_key,0,sizeof(m_ca_cert_key));
		memset(m_random,0,sizeof(m_random));
		memset(m_iv,0,sizeof(m_iv));
		memset(m_pswd,0,sizeof(m_pswd));
	}

	~gmssl_helper()
	{

	}

public:
	//初始化本地密钥对
	bool init_local_key(SM2_KEY * out_key)
	{
		bool ret = false;
		if (sm2_key_generate(out_key) == 1)
		{
			memcpy(&m_local_sm2key,out_key,sizeof(m_local_sm2key));
			return true;
		}
		else
			CLOG_ERROR("generate local key failed.");
		return ret;
	}
	//取得本地秘钥对
	bool get_local_key(SM2_KEY * out_key)
	{
		memcpy(out_key,&m_local_sm2key,sizeof(m_local_sm2key));
		return true;
	}
	//检查证书有效性;如果有效,返回true并提取证书中的公钥,否则返回false
	bool check_cert_validity(FILE* sign_fp)
	{
		bool ret = false;
		uint8_t cacert[1024] = {};//ca中间证书
		size_t cacertlen = 0;
		uint8_t signcert[1024] = {};//client签名证书
		size_t signcertlen = 0;

		char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
		size_t signer_id_len = 0;
		strcpy(signer_id, SM2_DEFAULT_ID);
		signer_id_len = strlen(SM2_DEFAULT_ID);

		const uint8_t *issuer = NULL;
		size_t issuer_len = 0;
		const uint8_t *serial = NULL;
		size_t serial_len = 0;
		const uint8_t *subject = NULL;
		size_t subject_len = 0;
		
		FILE *ca_fp = fmemopen((void*)s_ca_cert_data,strlen(s_ca_cert_data),"r");

		if (sign_fp)
		{
			if (x509_cert_from_pem(signcert,&signcertlen,sizeof(signcert),sign_fp) != 1
				|| x509_cert_get_issuer_and_serial_number(signcert, signcertlen, &issuer, &issuer_len, &serial, &serial_len) != 1
				|| x509_cert_get_subject(signcert, signcertlen, &subject, &subject_len) != 1)
			{
				CLOG_ERROR("load sign cert failed.");
			}
			else
			{
				// CLOG_PMSGD(issuer,issuer_len,"get issuer:");
				// CLOG_PMSGD(subject,subject_len,"get subject:");
				//CLOG_PMSGD(serial,serial_len,"get serial:");
				//加载CA中间证书
				if (ca_fp)
				{
					if (x509_cert_from_pem_by_subject(cacert, &cacertlen, sizeof(cacert), issuer, issuer_len, ca_fp) != 1)
						CLOG_ERROR("get pem by subject failed");
					else
					{
						if (x509_cert_verify_by_ca_cert(signcert, signcertlen, cacert, cacertlen,signer_id, signer_id_len) < 0)
							CLOG_ERROR("verify CA certificate failed");
						else
							ret = true;//校验通过
					}
				}
				else
					CLOG_ERROR("open ca cert failed.");
			}
		}
		if (ca_fp)
			fclose(ca_fp);
		if (ret)
		{//如果证书合法，那么提取对端公钥
			memset(&m_client_sm2key,0,sizeof(m_client_sm2key));
			if (x509_cert_get_subject_public_key(signcert, signcertlen,&m_client_sm2key) != 1)
			{
				CLOG_ERROR("get remote pub key failed.");
				ret = false;
			}
		}
		
		return ret;
	}
	//sm2算法公钥验签
	bool gm_sm2_verify_sign(const uint8_t * in_data, const size_t in_len, const uint8_t * in_sign)
	{
		// CLOG_PMSG(in_data, in_len, "real data:");
		// CLOG_PMSG(in_sign, 64, "sign:");
		bool ret = false;
		char *id = SM2_DEFAULT_ID;
		SM2_SIGN_CTX sm2_sc;
		uint8_t asn1_signature[SM2_MAX_SIGNATURE_SIZE] = { 0 };
		size_t asn1_len = 0;
		
		//先将原始ECDSA签名转asn.1编码
		gm_raw_to_asn1(in_sign,asn1_signature,&asn1_len);
		// CLOG_PMSG("hex", asn1_signature, asn1_len, "asn1 sign:");
		//然后开始验签
		if (sm2_verify_init(&sm2_sc, &m_client_sm2key, id, strlen(id)) == 1)
		{
			if (sm2_verify_update(&sm2_sc, in_data, in_len) == 1)
			{
				if (sm2_verify_finish(&sm2_sc, asn1_signature, asn1_len) == 1)
					ret = true;
				else	
					printf("sm2 verify failed");
			}
			else
				printf("sm2 verify update failed");
		}
		else
			printf("sm2 verify init failed");
		return ret;
	}
	//sm2算法公钥加密,in_data是待加密内容
	bool gm_sm2_encrypt(const uint8_t * in_data, const size_t in_len, uint8_t * out_data, size_t * out_len)
	{
		bool ret = false;
		SM2_CIPHERTEXT sm2_c;
		if (sm2_do_encrypt(&m_client_sm2key, in_data, in_len, &sm2_c) == 1)
		{
			if (sm2_der2nop(&sm2_c,out_data,out_len) == 1)
				ret = true;
		}
		else
			CLOG_ERROR("sm2 encrypt failed!");
		return ret;
	}
	//sm2算法私钥解密,in_data是待解密内容
	bool gm_sm2_decrypt(const uint8_t * in_data, const size_t in_len, uint8_t * out_data, size_t * out_len)
	{
		bool ret = false;
		uint8_t decrypted_chunk[SM2_MAX_PLAINTEXT_SIZE] = {};
        size_t decrypted_chunk_size = SM2_MAX_PLAINTEXT_SIZE;

		SM2_CIPHERTEXT sm2_c;
		sm2_nop2der(&sm2_c, in_data, in_len);
		if (sm2_do_decrypt(&m_local_sm2key,&sm2_c, decrypted_chunk, &decrypted_chunk_size) == 1)
		{
			if (decrypted_chunk_size > *out_len)
				CLOG_ERROR("out buffer is too small.");
			else
			{
				memcpy(out_data,decrypted_chunk,decrypted_chunk_size);
				*out_len = decrypted_chunk_size;
				ret = true;
			}
		}
		else
			CLOG_ERROR("sm2 decrypt failed!");
		return ret;
	}
	//sm4算法加密
	bool gm_sm4_encrypt(const uint8_t* in_data, const size_t in_len, uint8_t* out_data, size_t* out_len)
	{
		SM4_CBC_CTX sm4cc;
		int sm4_ret = -1;

		size_t tmp_len = 0;
		sm4_ret = sm4_cbc_encrypt_init(&sm4cc, m_pswd, m_iv);
		sm4_ret = sm4_cbc_encrypt_update(&sm4cc, in_data, in_len, out_data, out_len);
		sm4_ret = sm4_cbc_encrypt_finish(&sm4cc, out_data + *out_len, &tmp_len);
		*out_len += tmp_len;
		return (sm4_ret == 1);
	}
	//sm4算法解密
	bool gm_sm4_decrypt(const uint8_t * in_data, const size_t in_len, uint8_t * out_data, size_t * out_len)
	{
		SM4_CBC_CTX sm4cc;
		int sm4_ret = -1;

		// CLOG_PMSGD(in_data,in_len,"sm4 in data:");
		// CLOG_PMSGD(m_pswd,16,"sm4 pswd:");
		// CLOG_PMSGD(m_iv,16,"sm4 iv:");
		
		size_t tmp_len = 0;
		sm4_ret = sm4_cbc_decrypt_init(&sm4cc, m_pswd, m_iv);
		sm4_ret = sm4_cbc_decrypt_update(&sm4cc, in_data, in_len, out_data, out_len);
		sm4_ret = sm4_cbc_decrypt_finish(&sm4cc, out_data + *out_len, &tmp_len);
		*out_len += tmp_len;
		return (sm4_ret == 1);
	}
	//存储对端随机数R1,8字节,输出本地随机数R2,8字节
	bool set_remote_random(const uint8_t *in_random,uint8_t * out_random)
	{
		memcpy(m_random,in_random,8);//存储对端随机数
		//生成本地随机数;先sm3,然后取结果的前8字节和R1异或
		uint8_t dgst[32] = {0};
		SM3_CTX sm3c;
		sm3_update(&sm3c,in_random,8);
		sm3_finish(&sm3c,dgst);
		sm3_digest(in_random,8,dgst);
		for (size_t i = 0; i < 8; ++i)
        	m_random[i + 8] = m_random[i] ^ dgst[i];

		if (out_random)
		{
			memcpy(out_random,m_random + 8,8);
			//CLOG_PMSGD(out_random,8,"local random:");
		}
		return true;
	}
	//得到对端和本地随机数,8字节
	bool get_store_random(uint8_t * out_random)
	{
		memcpy(out_random,m_random,16);
		return true;
	}
	//设置IV,16字节
	bool set_sm4_iv(const uint8_t * in_iv)
	{
		memcpy(m_iv,in_iv,16);
		return true;
	}
	// //得到IV,16字节;暂时不需要
	// bool get_sm4_iv(uint8_t * out_iv)
	// {
	// 	memcpy(out_iv,m_iv,16);
	// 	return true;
	// }
	//设置sm4密钥,16字节
	bool set_sm4_pswd(const uint8_t * in_key)
	{
		memcpy(m_pswd,in_key,16);
		return true;
	}

protected:
	//将原始数据(R,S)转换为ASN.1格式,ASN.1格式为DER编码,其长度为70-72字节不定
	bool gm_raw_to_asn1(const uint8_t *in_data, uint8_t *out_buff, size_t *out_len) 
	{
	    bool ret = false;
		size_t offset = 0;
		
		// Start with SEQUENCE
		out_buff[offset++] = 0x30; // SEQUENCE tag
		offset++; // Skip length byte temporarily
		
		// Write r value
		out_buff[offset++] = 0x02; // INTEGER tag
		if (in_data[0] & 0x80) {
			out_buff[offset++] = 0x21; // length 33 for r (32 + 1 for leading zero)
			out_buff[offset++] = 0x00; // Add leading zero
			memcpy(out_buff + offset, in_data, 32);
			offset += 32;
		} else {
			out_buff[offset++] = 0x20; // length 32 for r
			memcpy(out_buff + offset, in_data, 32);
			offset += 32;
		}
		
		// Write s value
		out_buff[offset++] = 0x02; // INTEGER tag
		if (in_data[32] & 0x80) {
			out_buff[offset++] = 0x21; // length 33 for s (32 + 1 for leading zero)
			out_buff[offset++] = 0x00; // Add leading zero
			memcpy(out_buff + offset, in_data + 32, 32);
			offset += 32;
		} else {
			out_buff[offset++] = 0x20; // length 32 for s
			memcpy(out_buff + offset, in_data + 32, 32);
			offset += 32;
		}
		
		// Now write the actual sequence length
		out_buff[1] = offset - 2; // Total length minus sequence tag and length byte
		
		*out_len = offset;
		ret = true;
		
		return ret;
	}
	//将ASN.1格式数据转换为原始数据(R,S),原始数据长度为64字节固定
	bool gm_asn1_to_raw(const uint8_t *in_data, const size_t in_len, uint8_t *out_buff)
	{
		bool ret = false;
		size_t offset = 0;
		
		// Basic format validation
		if (in_data == NULL || out_buff == NULL || in_len < 6) {
			return ret;
		}
		
		// Check sequence tag
		if (in_data[offset++] != 0x30) {
			return ret;
		}
		
		// Get and validate sequence length
		size_t seq_len = in_data[offset++];
		if (seq_len + 2 != in_len) {
			return ret;
		}
		
		// Process r value
		if (in_data[offset++] != 0x02) { // INTEGER tag for r
			return ret;
		}
		
		size_t r_len = in_data[offset++];
		if (r_len != 0x20 && r_len != 0x21) {
			return ret;
		}
		
		const uint8_t *r_start = in_data + offset;
		if (r_len == 0x21) {
			// Skip leading zero if present
			if (r_start[0] != 0x00) {
				return ret;
			}
			r_start++;
		}
		offset += r_len;
		
		// Process s value
		if (in_data[offset++] != 0x02) { // INTEGER tag for s
			return ret;
		}
		
		size_t s_len = in_data[offset++];
		if (s_len != 0x20 && s_len != 0x21) {
			return ret;
		}
		
		const uint8_t *s_start = in_data + offset;
		if (s_len == 0x21) {
			// Skip leading zero if present
			if (s_start[0] != 0x00) {
				return ret;
			}
			s_start++;
		}
		
		// Copy r and s values to output buffer
		memcpy(out_buff, r_start, 32);
		memcpy(out_buff + 32, s_start, 32);
		
		ret = true;
		return ret;
	}
	//sm2加密der转04非压缩格式;type默认为1,c1c3c2格式;0则为c1c2c3格式
	int sm2_der2nop(const SM2_CIPHERTEXT * sm2der,uint8_t * out_data,size_t * out_len,int type = 1)
	{
		int ret = 1;
		*out_len = SM2_MIN_XYHASH_SIZE + size_t(sm2der->ciphertext_size);
		size_t pos = 0;
		memcpy(out_data + pos,sm2der->point.x, sizeof(sm2der->point.x));
		pos += sizeof(sm2der->point.x);
		memcpy(out_data + pos,sm2der->point.y,sizeof(sm2der->point.y));
		pos += sizeof(sm2der->point.y);
		if (type == 1)
		{//c1c3c2
			memcpy(out_data + pos,sm2der->hash, sizeof(sm2der->hash));
			pos += sizeof(sm2der->hash);
			memcpy(out_data + pos,sm2der->ciphertext,sm2der->ciphertext_size);
		}
		else
		{//c1c2c3
			memcpy(out_data + pos,sm2der->ciphertext,sm2der->ciphertext_size);
			pos += sm2der->ciphertext_size;
			memcpy(out_data + pos,sm2der->hash, sizeof(sm2der->hash));
		}
		return ret;	
	}
	//sm2加密04非压缩格式转der;type默认为1,c1c3c2格式;0则为c1c2c3格式
	int sm2_nop2der(SM2_CIPHERTEXT * out_der, const uint8_t * in_data, const size_t in_len,int type = 1)
	{
		int ret = 1;
		if (in_len < (SM2_MIN_XYHASH_SIZE + 1))
			return -1;
		size_t pos = 0;
		memset(out_der,0,sizeof(*out_der));
		memcpy(out_der->point.x, in_data + pos, sizeof(out_der->point.x));
		pos += sizeof(out_der->point.x);
		memcpy(out_der->point.y, in_data + pos, sizeof(out_der->point.y));
		pos += sizeof(out_der->point.y);
		if (type == 1)
		{//c1c3c2
			memcpy(out_der->hash, in_data + pos, sizeof(out_der->hash));
			pos += sizeof(out_der->hash);
			out_der->ciphertext_size = (uint8_t)(in_len - pos);
			memcpy(out_der->ciphertext,in_data + pos,out_der->ciphertext_size);
		}
		else
		{//c1c2c3
			out_der->ciphertext_size = (uint8_t)(in_len - pos - sizeof(out_der->hash));
			memcpy(out_der->ciphertext, in_data + pos, out_der->ciphertext_size);
			pos += out_der->ciphertext_size;
			memcpy(out_der->hash,in_data + pos,sizeof(out_der->hash));
		}
		return ret;
	}
private:
	SM2_KEY m_ca_cert_key;//CA中间证书密钥对
	SM2_KEY m_local_sm2key;//服务端(本地)密钥对,包含公钥和私钥
	SM2_KEY m_client_sm2key;//客户端(对端)密钥对,仅公钥
	uint8_t m_random[16];//随机数,前8字节为客户端生成,后8字节为服务器生成
	uint8_t m_iv[16];//SM4的IV
	uint8_t m_pswd[16];//SM4的密码
};



#endif //__GMSSL_HELPER__HPP__