#include "../include/cryptography.h"


int Cryptography::AES_cipher_key_init(unsigned char *key_data, int key_data_len, unsigned char *salt, unsigned int rounds, unsigned char *key, unsigned char *iv) {
	int result = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, key_data_len, rounds, key, iv);
	
	if (result != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	return 1;
}

int Cryptography::AES_encrypt_init(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *key, unsigned char *iv) {
	if (EVP_CIPHER_CTX_init(encrypt_ctx) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0)
	{
		return EVP_EncryptInit_ex_ERROR;
	}

	return 1;
}

int Cryptography::AES_decrypt_init(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *key, unsigned char *iv) {
	if (EVP_CIPHER_CTX_init(encrypt_ctx) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_DecryptInit_ex(encrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	return 1;
}

int Cryptography::AES_init(unsigned char *key_data, int key_data_len, unsigned char *salt, unsigned int rounds, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	unsigned char key[32], iv[32];
	
	memset(key, 0, 32);
	memset(iv, 0, 32);

	int result = AES_cipher_key_init(key_data, key_data_len, salt, rounds, key, iv);

	if(result < 0) {
		return result;
	}

	result = AES_encrypt_init(e_ctx, key, iv);

	if(result < 0) {
		return result;
	}

	return AES_decrypt_init(d_ctx, key, iv);
}
