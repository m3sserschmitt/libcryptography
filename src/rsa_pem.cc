#include "../include/cryptography.h"


EVP_PKEY *Cryptography::create_private_RSA(std::string key)
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

EVP_PKEY *Cryptography::create_public_RSA(std::string key)
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

std::string Cryptography::get_public_PEM(EVP_PKEY *key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(keybio, key);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

std::string Cryptography::get_private_PEM(EVP_PKEY *key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(keybio, EVP_PKEY_get1_RSA(key), nullptr, nullptr, 0, nullptr, nullptr);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}
