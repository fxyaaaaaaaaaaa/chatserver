// #ifndef __GMSSL_HELPER__HPP__
// #define __GMSSL_HELPER__HPP__

// #include "./gmssl/include/gmssl/sm2.h"
// #include "./gmssl/include/gmssl/sm3.h"
// #include "./gmssl/include/gmssl/sm4.h"
// #include "./gmssl/include/gmssl/rand.h"



// class gmssl_helper
// {

// //sm4密码
// const char *s_sm4_pswd = "C35rQDuanA1tJyRH";
// //sm4向量
// const char *s_sm4_iv = "XRl57MC5QgFzbvZS";

// // CA中间证书,cacert.pem
// const char* s_ca_cert_data = "-----BEGIN CERTIFICATE-----\n"
// 								"MIIB6DCCAY6gAwIBAgIMI4AwRGN9s+Noch7zMAoGCCqBHM9VAYN1MGYxCzAJBgNV\n"
// 								"BAYTAkNOMREwDwYDVQQIEwhaaGVqaWFuZzERMA8GA1UEBxMISGFuZ3pob3UxDzAN\n"
// 								"BgNVBAoTBmhvb2t3ZTEPMA0GA1UECxMGaG9va3dlMQ8wDQYDVQQDEwZST09UQ0Ew\n"
// 								"HhcNMjUwMTAzMDYxNTU0WhcNMjYwMTAzMDYxNTU0WjBiMQswCQYDVQQGEwJDTjER\n"
// 								"MA8GA1UECBMIWmhlamlhbmcxETAPBgNVBAcTCEhhbmd6aG91MQ8wDQYDVQQKEwZo\n"
// 								"b29rd2UxDzANBgNVBAsTBmhvb2t3ZTELMAkGA1UEAxMCQ0EwWTATBgcqhkjOPQIB\n"
// 								"BggqgRzPVQGCLQNCAATJS4wLmuSAsN/R4CN5ZhRCuxQ+6zimXVRLMAv1qVs2PBKN\n"
// 								"ou4p2Vm4fMcePC+mnIDY6208J+JkkhOum580NUYRoyYwJDAOBgNVHQ8BAf8EBAMC\n"
// 								"AgQwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqgRzPVQGDdQNIADBFAiEA4Za90VSC\n"
// 								"8aVtUnrZJGzCajGRZASO4pbLmuN0ltvHIq8CIHAXKHSZl2nXxWenSG76Mnu+pzQL\n"
// 								"riy4A+8VyBZvgA2U\n"
// 								"-----END CERTIFICATE-----\n";

// public:
// 	gmssl_helper()
// 	{
// 		memset(&m_client_sm2key,0,sizeof(m_client_sm2key));
// 		memset(&m_local_sm2key,0,sizeof(m_local_sm2key));
// 		memset(&m_ca_cert_key,0,sizeof(m_ca_cert_key));
// 	}

// 	~gmssl_helper()
// 	{

// 	}

// public:
// 	//初始化本地密钥对
// 	bool init_local_key()
// 	{

// 	}
// 	//检查证书有效性;如果有效,返回true并提取证书中的公钥,否则返回false
// 	bool check_cert_validity(FILE* sign_fp)
// 	{
// 		bool ret = false;
// 		uint8_t cacert[1024] = {};//ca中间证书
// 		size_t cacertlen = 0;
// 		uint8_t signcert[1024] = {};//client签名证书
// 		size_t signcertlen = 0;

// 		char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
// 		size_t signer_id_len = 0;
// 		strcpy(signer_id, SM2_DEFAULT_ID);
// 		signer_id_len = strlen(SM2_DEFAULT_ID);

// 		const uint8_t *issuer = NULL;
// 		size_t issuer_len = 0;
// 		const uint8_t *serial = NULL;
// 		size_t serial_len = 0;
// 		const uint8_t *subject = NULL;
// 		size_t subject_len = 0;
		
// 		FILE *ca_fp = fmemopen((void*)s_ca_cert_data,strlen(s_ca_cert_data),"r");

// 		if (sign_fp)
// 		{
// 			if (x509_cert_from_pem(signcert,&signcertlen,sizeof(signcert),sign_fp) != 1
// 				|| x509_cert_get_issuer_and_serial_number(signcert, signcertlen, &issuer, &issuer_len, &serial, &serial_len) != 1
// 				|| x509_cert_get_subject(signcert, signcertlen, &subject, &subject_len) != 1)
// 			{
// 				CLOG_ERR("load sign cert failed.");
// 			}
// 			else
// 			{
// 				// CLOG_PMSGD(issuer,issuer_len,"get issuer:");
// 				// CLOG_PMSGD(subject,subject_len,"get subject:");
// 				CLOG_PMSGD(serial,serial_len,"get serial:");
// 				//加载CA中间证书
// 				if (ca_fp)
// 				{
// 					if (x509_cert_from_pem_by_subject(cacert, &cacertlen, sizeof(cacert), issuer, issuer_len, ca_fp) != 1)
// 						CLOG_ERR("get pem by subject failed");
// 					else
// 					{
// 						if (x509_cert_verify_by_ca_cert(signcert, signcertlen, cacert, cacertlen,signer_id, signer_id_len) < 0)
// 							CLOG_ERR("verify CA certificate failed");
// 						else
// 							ret = TRUE;//校验通过
// 					}
// 				}
// 				else
// 					CLOG_ERR("open ca cert failed.");
// 			}
// 		}
// 		if (ca_fp)
// 			fclose(ca_fp);
// 		if (ret)
// 		{//如果证书合法，那么提取对端公钥
// 			memset(&m_client_sm2key,0,sizeof(m_client_sm2key));
// 			if (x509_cert_get_subject_public_key(signcert, signcertlen,&m_client_sm2key) != 1)
// 			{
// 				CLOG_ERR("get remote pub key failed.");
// 				ret = FALSE;
// 			}
// 		}
// 		return ret;
// 	}
// private:
// 	SM2_KEY m_ca_cert_key;//CA中间证书密钥对
// 	SM2_KEY m_local_sm2key;//服务端(本地)密钥对
// 	SM2_KEY m_client_sm2key;//客户端(对端)密钥对
// };



// #endif //__GMSSL_HELPER__HPP__