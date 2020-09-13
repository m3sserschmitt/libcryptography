#include "../../include/v1/rsa.h"
#include "../../include/v1/base64.h"
#include "../../include/v1/errors.h"

int get_RSA_size(EVP_PKEY *key)
{
	return EVP_PKEY_size(key);
}

EVP_PKEY *create_private_RSA(std::string key)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	const char *c_string = key.c_str();
	BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

EVP_PKEY *create_public_RSA(std::string key)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	BIO *keybio;
	const char *c_string = key.c_str();

	keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

std::string get_public_PEM(EVP_PKEY *key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(keybio, key);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

std::string get_private_PEM(EVP_PKEY *key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(keybio, EVP_PKEY_get1_RSA(key), nullptr, nullptr, 0, nullptr, nullptr);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

int RSA_sign(EVP_PKEY *privKey, unsigned char *Msg, size_t MsgLen, unsigned char *EncMsg, size_t &MsgLenEnc)
{
	EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();

	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, privKey) <= 0)
	{
		return EVP_DigestSignInit_ERROR;
	}

	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
	{
		return EVP_DigestSignUpdate_ERROR;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &MsgLenEnc) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, EncMsg, &MsgLenEnc) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	EVP_MD_CTX_free(m_RSASignCtx);

	return 1;
}

int RSA_verify_signature(EVP_PKEY *pubKey, unsigned char *MsgHash, size_t MsgHashLen, unsigned char *Msg, size_t MsgLen, bool &Authentic)
{
	Authentic = false;

	EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();
	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
	{
		return EVP_DigestVerifyInit_ERROR;
	}
	// printf("checkpoint1\n");
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
	{
		return EVP_DigestVerifyUpdate_ERROR;
	}
	// printf("checkpoint2\n");
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	// printf("checkpoint3\n");
	if (AuthStatus == 1)
	{
		// printf("checkpoint4\n");
		Authentic = true;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		// printf("checkpoint4.5\n");
		return 1;
	}
	else if (AuthStatus == 0)
	{
		// printf("checkpoint5\n");
		Authentic = false;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else
	{
		// printf("checkpoint6\n");
		Authentic = false;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		return EVP_DigestVerifyFinal_ERROR;
	}
}

int RSA_encrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *pub_key)
{
	EVP_PKEY_CTX *encrypt_context = EVP_PKEY_CTX_new(pub_key, NULL);

	if (not encrypt_context)
	{
		return EVP_PKEY_CTX_new_ERROR;
	}

	if (EVP_PKEY_encrypt_init(encrypt_context) <= 0)
	{
		return EVP_PKEY_encrypt_init_ERROR;
	}

	if (EVP_PKEY_encrypt(encrypt_context, NULL, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_encrypt_ERROR;
	}

	if (EVP_PKEY_encrypt(encrypt_context, out, &outlen, in, inlen) < 0)
	{
		return EVP_PKEY_encrypt_ERROR;
	}

	EVP_PKEY_CTX_free(encrypt_context);

	return 1;
}

int RSA_decrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *priv_key)
{
	EVP_PKEY_CTX *decrypt_context = EVP_PKEY_CTX_new(priv_key, NULL);

	if (not decrypt_context)
	{
		return EVP_PKEY_CTX_new_ERROR;
	}

	if (EVP_PKEY_decrypt_init(decrypt_context) <= 0)
	{
		return EVP_PKEY_decrypt_init_ERROR;
	}

	if (EVP_PKEY_decrypt(decrypt_context, NULL, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_decrypt_ERROR;
	}

	if (EVP_PKEY_decrypt(decrypt_context, out, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_decrypt_ERROR;
	}

	EVP_PKEY_CTX_free(decrypt_context);

	return 1;
}