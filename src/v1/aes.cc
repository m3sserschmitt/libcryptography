#include "../../include/v1/aes.h"
#include "../../include/v1/errors.h"

#include <string.h>

size_t get_AES_encrypted_size(size_t plaintext_size)
{
	return plaintext_size + AES_BLOCK_SIZE;
}

size_t get_AES_decrypted_size(size_t ciphertext_size)
{
	return ciphertext_size - AES_BLOCK_SIZE;
}

int AES_encrypt_init(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *key_data, size_t keylen, unsigned char *salt, int rounds)
{
	unsigned char key[64] = {0};
	unsigned char iv[64] = {0};

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, keylen, rounds, key, iv) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

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

int AES_decrypt_init(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *key_data, size_t keylen, unsigned char *salt, int rounds)
{
	unsigned char key[64] = {0};
	unsigned char iv[64] = {0};

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, keylen, rounds, key, iv) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	if (EVP_CIPHER_CTX_init(decrypt_ctx) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	return 1;
}

int AES_init(unsigned char *key_data, int key_data_len, unsigned char *salt, unsigned int rounds, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
	int result = AES_encrypt_init(e_ctx, key_data, key_data_len, salt, rounds);

	if (result < 0)
	{
		return result;
	}

	return AES_decrypt_init(d_ctx, key_data, key_data_len, salt, rounds);
}

int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = inlen + AES_BLOCK_SIZE, f_len = 0;

	/* allows reusing of 'e' for multiple encryption cycles */
	if (EVP_EncryptInit_ex(encrypt_ctx, NULL, NULL, NULL, NULL) <= 0)
	{
		return EVP_EncryptInit_ex_ERROR;
	}

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */

	if (EVP_EncryptUpdate(encrypt_ctx, out, &c_len, in, inlen) <= 0)
	{
		return EVP_EncryptUpdate_ERROR;
	}

	/* update ciphertext with the final remaining bytes */
	if (EVP_EncryptFinal_ex(encrypt_ctx, out + c_len, &f_len) <= 0)
	{
		return EVP_EncryptFinal_ex_ERROR;
	}

	outlen = c_len + f_len;
	return 1;
}

int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen)
{
	/* plaintext will always be equal to or lesser than length of ciphertext*/
	int p_len = inlen, f_len = 0;

	if (EVP_DecryptInit_ex(decrypt_ctx, NULL, NULL, NULL, NULL) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	if (EVP_DecryptUpdate(decrypt_ctx, out, &p_len, in, inlen) <= 0)
	{
		return EVP_DecryptUpdate_ERROR;
	}

	if (EVP_DecryptFinal_ex(decrypt_ctx, out + p_len, &f_len) <= 0)
	{
		return EVP_DecryptFinal_ex_ERROR;
	}

	outlen = p_len + f_len;

	return 1;
}
