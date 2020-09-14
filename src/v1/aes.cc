#include "../../include/v1/aes.h"
#include "../../include/v1/errors.h"

#include <string.h>

size_t get_AES_encrypted_size(SIZE inlen)
{
	return inlen + AES_BLOCK_SIZE;
}

size_t get_AES_decrypted_size(SIZE inlen)
{
	return inlen - AES_BLOCK_SIZE;
}

int AES_encrypt_init(ENCRYPT_CTX encr, BYTES key_data, SIZE keylen, BYTES salt, int rounds)
{
	unsigned char key[64] = {0};
	unsigned char iv[64] = {0};

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, keylen, rounds, key, iv) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	if (EVP_CIPHER_CTX_init(encr) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_EncryptInit_ex(encr, EVP_aes_256_cbc(), NULL, key, iv) <= 0)
	{
		return EVP_EncryptInit_ex_ERROR;
	}

	return 1;
}

int AES_decrypt_init(DECRYPT_CTX decr, BYTES key_data, SIZE keylen, BYTES salt, int rounds)
{
	unsigned char key[64] = {0};
	unsigned char iv[64] = {0};

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, keylen, rounds, key, iv) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	if (EVP_CIPHER_CTX_init(decr) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_DecryptInit_ex(decr, EVP_aes_256_cbc(), NULL, key, iv) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	return 1;
}

int AES_init(BYTES key, SIZE keylen, BYTES salt, int rounds, ENCRYPT_CTX encr, DECRYPT_CTX decr)
{
	int result = AES_encrypt_init(encr, key, keylen, salt, rounds);

	if (result < 0)
	{
		return result;
	}

	return AES_decrypt_init(decr, key, keylen, salt, rounds);
}

int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = inlen + AES_BLOCK_SIZE, f_len = 0;

	/* allows reusing of 'e' for multiple encryption cycles */
	if (EVP_EncryptInit_ex(encr, NULL, NULL, NULL, NULL) <= 0)
	{
		return EVP_EncryptInit_ex_ERROR;
	}

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */

	if (EVP_EncryptUpdate(encr, out, &c_len, in, inlen) <= 0)
	{
		return EVP_EncryptUpdate_ERROR;
	}

	/* update ciphertext with the final remaining bytes */
	if (EVP_EncryptFinal_ex(encr, out + c_len, &f_len) <= 0)
	{
		return EVP_EncryptFinal_ex_ERROR;
	}

	outlen = c_len + f_len;
	return 1;
}

int AES_decrypt(DECRYPT_CTX decr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	/* plaintext will always be equal to or lesser than length of ciphertext*/
	int p_len = inlen, f_len = 0;

	if (EVP_DecryptInit_ex(decr, NULL, NULL, NULL, NULL) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	if (EVP_DecryptUpdate(decr, out, &p_len, in, inlen) <= 0)
	{
		return EVP_DecryptUpdate_ERROR;
	}

	if (EVP_DecryptFinal_ex(decr, out + p_len, &f_len) <= 0)
	{
		return EVP_DecryptFinal_ex_ERROR;
	}

	outlen = p_len + f_len;

	return 1;
}
