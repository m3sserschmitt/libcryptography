#include "../../include/v1/rsa.h"
#include "../../include/v1/base64.h"
#include "../../include/v1/errors.h"

int get_RSA_size(KEY key)
{
	return EVP_PKEY_size(key);
}

PRIVATE_KEY create_private_RSA(std::string key)
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

PUBLIC_KEY create_public_RSA(std::string key_pem)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	BIO *keybio;
	const char *c_string = key_pem.c_str();

	keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

void RSA_free_key(KEY key) {
	EVP_PKEY_free(key);
}

std::string get_public_PEM(PUBLIC_KEY key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(keybio, key);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

std::string get_private_PEM(PRIVATE_KEY key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(keybio, EVP_PKEY_get1_RSA(key), nullptr, nullptr, 0, nullptr, nullptr);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen)
{
	EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();

	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, key) <= 0)
	{
		return EVP_DigestSignInit_ERROR;
	}

	if (EVP_DigestSignUpdate(m_RSASignCtx, in, inlen) <= 0)
	{
		return EVP_DigestSignUpdate_ERROR;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &signlen) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, signature, &signlen) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	EVP_MD_CTX_free(m_RSASignCtx);

	return 1;
}

int RSA_verify_signature(PUBLIC_KEY key, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic)
{
	authentic = false;

	EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();
	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, key) <= 0)
	{
		return EVP_DigestVerifyInit_ERROR;
	}
	
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, data, datalen) <= 0)
	{
		return EVP_DigestVerifyUpdate_ERROR;
	}
	
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, hash, hashlen);
	
	if (AuthStatus == 1)
	{
		authentic = true;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else if (AuthStatus == 0)
	{
		authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else
	{
		authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return EVP_DigestVerifyFinal_ERROR;
	}
}

int RSA_encrypt(BYTES in, SIZE inlen, BYTES out, SIZE &outlen, PUBLIC_KEY key)
{
	EVP_PKEY_CTX *encrypt_context = EVP_PKEY_CTX_new(key, NULL);

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

int RSA_decrypt(BYTES in, SIZE inlen, BYTES out, SIZE &outlen, PRIVATE_KEY key)
{
	EVP_PKEY_CTX *decrypt_context = EVP_PKEY_CTX_new(key, NULL);

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