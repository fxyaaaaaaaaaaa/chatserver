#include"gmssl-client.h"
gmssl_helpe &gmssl_helpe::get_instance()
{
	static gmssl_helpe instance;
	return instance;
};
bool gmssl_helpe::load_certification(std::string fullpath)
{
	// 二进制打开
	std::ifstream file(fullpath, std::ios::binary);
	if (!file)
	{
		//CLOG_ERR("open certificationfile error!");
		return false;
	}
	// 计算文件大小
	file.seekg(0, std::ios::end);
	std::size_t filesize = file.tellg();
	file.seekg(0, std::ios::beg);

	// 读取文件内容
	gmssl_helpe::certification_len = filesize;
	if (!file.read(reinterpret_cast<char *>(gmssl_helpe::get_instance().certification), filesize))
	{
		//printf("read certificationfile error!");
		return false;
	}
	return true;
}
bool gmssl_helpe::load_private_key(const std::string &pem_file)
{
	FILE *fp = fopen(pem_file.c_str(), "r");
	if (!fp)
	{
		//CLOG_ERR("Failed to open private PEM file.");
		return false;
	}

	if (sm2_private_key_info_decrypt_from_pem(&m_ca_1_key, "Hookwe@456", fp) != 1)
	{
		//CLOG_ERR("Failed to load private key from PEM.");
		fclose(fp);
		return false;
	}

	fclose(fp);

	return true;
}
int gmssl_helpe::sm2_nop2der(SM2_CIPHERTEXT *out_der, const uint8_t *in_data, const size_t in_len, int type =1 )
{
	int ret = 1;
	if (in_len < (SM2_MIN_XYHASH_SIZE + 1))
		return -1;
	size_t pos = 0;
	memset(out_der, 0, sizeof(*out_der));
	memcpy(out_der->point.x, in_data + pos, sizeof(out_der->point.x));
	pos += sizeof(out_der->point.x);
	memcpy(out_der->point.y, in_data + pos, sizeof(out_der->point.y));
	pos += sizeof(out_der->point.y);
	if (type == 1)
	{ // c1c3c2
		memcpy(out_der->hash, in_data + pos, sizeof(out_der->hash));
		pos += sizeof(out_der->hash);
		out_der->ciphertext_size = (uint8_t)(in_len - pos);
		memcpy(out_der->ciphertext, in_data + pos, out_der->ciphertext_size);
	}
	else
	{ // c1c2c3
		out_der->ciphertext_size = (uint8_t)(in_len - pos - sizeof(out_der->hash));
		memcpy(out_der->ciphertext, in_data + pos, out_der->ciphertext_size);
		pos += out_der->ciphertext_size;
		memcpy(out_der->hash, in_data + pos, sizeof(out_der->hash));
	}

	return ret;
}
int gmssl_helpe::sm2_slice_decrypt(SM2_KEY *sm2key, const uint8_t *in_data, const int in_len, uint8_t *out_data, size_t *out_len)
{
	if (in_len <= 0 || !in_data || !out_data || !out_len)
	{
		return -1; // 错误输入
	}

	const size_t max_plaintext_size = SM2_MAX_PLAINTEXT_SIZE;
	const size_t max_ciphertext_size = max_plaintext_size + 32;

	size_t total_len = 0;
	size_t num_chunks = (in_len + max_ciphertext_size - 1) / max_ciphertext_size; // 计算分片数量

	for (size_t i = 0; i < num_chunks; ++i)
	{
		size_t offset = i * max_ciphertext_size;
		size_t chunk_size = (i == num_chunks - 1) ? (in_len - offset) : max_ciphertext_size;

		// 解密每个片段
		uint8_t chunk[max_ciphertext_size] = {};
		uint8_t decrypted_chunk[max_plaintext_size] = {};
		size_t decrypted_chunk_size = sizeof(decrypted_chunk);

		memcpy(chunk, in_data + offset, chunk_size);
		SM2_CIPHERTEXT SM2C;

		gmssl_helpe::get_instance().sm2_nop2der(&SM2C, chunk, chunk_size);
		// CLOG_PMSGD(SM2C.point.x,32,"get x:");
		// CLOG_PMSGD(SM2C.point.y,32,"get y:");
		// CLOG_PMSGD(SM2C.hash,32,"get hash:");
		// CLOG_PMSGD(SM2C.ciphertext,SM2C.ciphertext_size,"get cip:");
		// CLOG_PMSGD(sm2key->private_key,32,"pri key:");
		if (sm2_do_decrypt(sm2key, &SM2C, decrypted_chunk, &decrypted_chunk_size) != 1)
		{
			return -2; // 解密失败
		}

		// 将解密后的数据拼接到输出缓冲区
		if (total_len + decrypted_chunk_size > *out_len)
		{
			throw std::runtime_error("sm2 slice decrypt:缓冲区不足!");
			return -3; // 输出缓冲区不足
		}

		memcpy(out_data + total_len, decrypted_chunk, decrypted_chunk_size);
		total_len += decrypted_chunk_size;
	}

	*out_len = total_len;
	return 1; // 成功
}
void gmssl_helpe::generate_random_numbers(UCHAR *out_data, int type)
{

	// 随机数生成器
	std::random_device rd;							 // 获取随机数种子
	std::mt19937_64 mt(rd());						 // 使用64位梅森旋转算法
	std::uniform_int_distribution<int> dist(0, 255); // 指定范围为0到255

	// type == 0 生成R1R2所需要的随机数
	// type == 1 生成IV
	//...
	if (type == 0)
	{
		// 生成8个随机字节
		for (int i = 0; i < 8; ++i)
		{
			out_data[i] = (static_cast<unsigned char>(dist(mt)));
		}
	}
	else if (type == 1)
	{
		for (int i = 0; i < 16; ++i)
		{
			out_data[i] = (static_cast<unsigned char>(dist(mt)));
		}
	}
}
bool gmssl_helpe::verify_r2(UCHAR *r2)
{
	SM3_CTX ctx;
	sm3_init(&ctx); // 初始化上下文

	// 更新哈希值
	sm3_update(&ctx, gmssl_helpe::get_instance().r1, 8);

	// 完成并获取哈希值
	UCHAR hash[32]; // SM3 输出长度为 32 字节
	sm3_finish(&ctx, hash);

	// 取出摘要的前8字节

	UCHAR hash8[8] = "";
	memcpy(hash8, hash, 8);

	// 进行^计算出R2*
	for (int i = 0; i < 8; i++)
	{
		hash8[i] = hash8[i] ^ gmssl_helpe::get_instance().r1[i];
	}
	if (!memcmp(r2, hash8, 8))
	{
		return true;
	}
	return false;
}
int gmssl_helpe::sm2_der2nop(const SM2_CIPHERTEXT *sm2der, uint8_t *out_data, size_t *out_len, int type = 1)
{
	int ret = 1;
	*out_len = SM2_MIN_XYHASH_SIZE + size_t(sm2der->ciphertext_size);
	size_t pos = 0;
	memcpy(out_data + pos, sm2der->point.x, sizeof(sm2der->point.x));
	pos += sizeof(sm2der->point.x);
	memcpy(out_data + pos, sm2der->point.y, sizeof(sm2der->point.y));
	pos += sizeof(sm2der->point.y);
	if (type == 1)
	{ // c1c3c2
		memcpy(out_data + pos, sm2der->hash, sizeof(sm2der->hash));
		pos += sizeof(sm2der->hash);
		memcpy(out_data + pos, sm2der->ciphertext, sm2der->ciphertext_size);
	}
	else
	{ // c1c2c3
		memcpy(out_data + pos, sm2der->ciphertext, sm2der->ciphertext_size);
		pos += sm2der->ciphertext_size;
		memcpy(out_data + pos, sm2der->hash, sizeof(sm2der->hash));
	}
	return ret;
}
bool gmssl_helpe::gm_sm2_encrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t *out_len)
{
	bool ret = false;
	SM2_CIPHERTEXT sm2c;
	if (sm2_do_encrypt(&gmssl_helpe::get_instance().m_server_sm2key, in_data, in_len, &sm2c) == 1)
	{
		if (sm2_der2nop(&sm2c, out_data, out_len) == 1)
			ret = true;
	}
	else
		//printf("sm2 encrypt failed.");
	return ret;
}
BOOL gmssl_helpe::gm_raw_to_asn1(const uint8_t *in_data, uint8_t *out_buff, size_t *out_len)
{
	BOOL ret = false;
	size_t offset = 0;

	// Start with SEQUENCE
	out_buff[offset++] = 0x30; // SEQUENCE tag
	offset++;				   // Skip length byte temporarily

	// Write r value
	out_buff[offset++] = 0x02; // INTEGER tag
	if (in_data[0] & 0x80)
	{
		out_buff[offset++] = 0x21; // length 33 for r (32 + 1 for leading zero)
		out_buff[offset++] = 0x00; // Add leading zero
		memcpy(out_buff + offset, in_data, 32);
		offset += 32;
	}
	else
	{
		out_buff[offset++] = 0x20; // length 32 for r
		memcpy(out_buff + offset, in_data, 32);
		offset += 32;
	}

	// Write s value
	out_buff[offset++] = 0x02; // INTEGER tag
	if (in_data[32] & 0x80)
	{
		out_buff[offset++] = 0x21; // length 33 for s (32 + 1 for leading zero)
		out_buff[offset++] = 0x00; // Add leading zero
		memcpy(out_buff + offset, in_data + 32, 32);
		offset += 32;
	}
	else
	{
		out_buff[offset++] = 0x20; // length 32 for s
		memcpy(out_buff + offset, in_data + 32, 32);
		offset += 32;
	}

	// Now write the actual sequence length
	out_buff[1] = offset - 2; // Total length minus sequence tag and length byte

	*out_len = offset;
	ret = 1;

	return ret;
}
BOOL gmssl_helpe::wa_asn1_to_raw(const uint8_t *in_data, const size_t in_len, uint8_t *out_buff)
{
	BOOL ret = false;
	size_t offset = 0;

	// Basic format validation
	if (in_data == NULL || out_buff == NULL || in_len < 6)
	{
		return ret;
	}

	// Check sequence tag
	if (in_data[offset++] != 0x30)
	{
		return ret;
	}

	// Get and validate sequence length
	size_t seq_len = in_data[offset++];
	if (seq_len + 2 != in_len)
	{
		return ret;
	}

	// Process r value
	if (in_data[offset++] != 0x02)
	{ // INTEGER tag for r
		return ret;
	}

	size_t r_len = in_data[offset++];
	if (r_len != 0x20 && r_len != 0x21)
	{
		return ret;
	}

	const uint8_t *r_start = in_data + offset;
	if (r_len == 0x21)
	{
		// Skip leading zero if present
		if (r_start[0] != 0x00)
		{
			return ret;
		}
		r_start++;
	}
	offset += r_len;

	// Process s value
	if (in_data[offset++] != 0x02)
	{ // INTEGER tag for s
		return ret;
	}

	size_t s_len = in_data[offset++];
	if (s_len != 0x20 && s_len != 0x21)
	{
		return ret;
	}

	const uint8_t *s_start = in_data + offset;
	if (s_len == 0x21)
	{
		// Skip leading zero if present
		if (s_start[0] != 0x00)
		{
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
BOOL gmssl_helpe::wa_load_pub_key(const char *sign_cert_path, void *out_public_key)
{
	printf("11111\n");
	BOOL ret = false;

	uint8_t signcert[1024] = {0};
	size_t signcertlen = 0;

	char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
	size_t signer_id_len = 0;
	strcpy(signer_id, SM2_DEFAULT_ID);
	signer_id_len = strlen(SM2_DEFAULT_ID);

	FILE *signfp = NULL;
	
	signfp = fopen(CA_PATH, "rb");

	const uint8_t *issuer;
	size_t issuer_len = 0;
	const uint8_t *serial;
	size_t serial_len = 0;
	const uint8_t *subject;
	size_t subject_len = 0;

	// 先加载待验证的证书
	if (signfp)
	{
		if (x509_cert_from_pem(signcert, &signcertlen, sizeof(signcert), signfp) != 1 || x509_cert_get_issuer_and_serial_number(signcert, signcertlen, &issuer, &issuer_len, &serial, &serial_len) != 1 || x509_cert_get_subject(signcert, signcertlen, &subject, &subject_len) != 1)
		{
			// //CLOG_ERR("load sign cert failed.");
			printf("\n 证书验证不确 \n");
		}
		else
		{
			printf("\n 证书验证正确 \n");
		}
		// CLOG_PMSG("hex",serial,serial_len,"get serial:");
	}

	if (x509_cert_get_subject_public_key(signcert, signcertlen, (SM2_KEY *)out_public_key) == 1)
	{
		// CLOG_PMSG("hex",out_public_key->public_key.x,sizeof(out_public_key->public_key.x),"pub x");
		// CLOG_PMSG("hex",out_public_key->public_key.y,sizeof(out_public_key->public_key.y),"pub y");
		ret = true;
	}
	else
	{
		printf("get remote pub key failed.");
	}
		

	if (signfp)
		fclose(signfp);
	return ret;
}
size_t gmssl_helpe::wa_sm2_sign_data(void *pri_key, const uint8_t *in_data, const size_t in_len, uint8_t *out_buff)
{
	// CLOG_PMSG("hex",in_data,in_len,"send buff:");
	size_t ret_len = 0;
	SM2_SIGN_CTX sign_ctx;
	char *id = SM2_DEFAULT_ID;
	uint8_t asn1_signature[SM2_MAX_SIGNATURE_SIZE] = {0};
	size_t asn1_len = 0;

	do
	{
		if (sm2_sign_init(&sign_ctx, (SM2_KEY *)pri_key, id, strlen(id)) != 1)
		{
			//CLOG_ERR("sm2 init failed.");
			break;
		}

		if (sm2_sign_update(&sign_ctx, in_data, in_len) != 1)
		{
			//CLOG_ERR("sm2 update failed.");
			break;
		}

		if (sm2_sign_finish(&sign_ctx, asn1_signature, &asn1_len) != 1)
		{
			//CLOG_ERR("sm2 finish failed.");
			break;
		}
		//printf("asn1_len =%d ans1=");
		for (int i = 0; i < asn1_len; i++)
		{
			//printf("%02x", asn1_signature[i]);
		}
		//printf("\n");
		// //printf("\nhex=%s,asn1_len=%d,asn1 sign data:",asn1_signature,asn1_len);
		if (wa_asn1_to_raw(asn1_signature, asn1_len, out_buff))
			ret_len = 64;

		//printf("raw:");
		for (int i = 0; i < 64; i++)
		{
			//printf("%02x", out_buff[i]);
		}
		//printf("\n");
		// CLOG_PMSG("hex",out_buff,ret_len,"raw sign data:");
	} while (false);

	// gmssl_secure_clear(&sign_ctx, sizeof(sign_ctx));
	return ret_len;
}
bool gmssl_helpe::gm_sm4_encrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t &out_len)
{
	SM4_CBC_CTX sm4cc;
	int sm4_ret = -1;
	UCHAR *m_pswd = gmssl_helpe::get_instance().sm4_key;
	UCHAR *m_iv = gmssl_helpe::get_instance().s_sm4_iv;

	size_t tmp_len = 0;

	// 初始化加密上下文
	sm4_ret = sm4_cbc_encrypt_init(&sm4cc, m_pswd, m_iv);

	// 执行加密操作
	sm4_ret = sm4_cbc_encrypt_update(&sm4cc, in_data, in_len, out_data, &out_len);

	// 完成加密并处理填充

	sm4_ret = sm4_cbc_encrypt_finish(&sm4cc, out_data + out_len, &tmp_len);

	out_len += tmp_len;
	return (sm4_ret == 1);
}

bool gmssl_helpe::gm_sm4_decrypt(const uint8_t *in_data, const size_t in_len, uint8_t *out_data, size_t *out_len)
{
	SM4_CBC_CTX sm4cc;
	int sm4_ret = -1;
	size_t tmp_len = 0;
	UCHAR *m_pswd = gmssl_helpe::get_instance().sm4_key;
	UCHAR *m_iv = gmssl_helpe::get_instance().s_sm4_iv;
	sm4_ret = sm4_cbc_decrypt_init(&sm4cc, m_pswd, m_iv);
	sm4_ret = sm4_cbc_decrypt_update(&sm4cc, in_data, in_len, out_data, out_len);
	sm4_ret = sm4_cbc_decrypt_finish(&sm4cc, out_data + *out_len, &tmp_len);
	*out_len += tmp_len;
	return (sm4_ret == 1);
}
// Init sm Request