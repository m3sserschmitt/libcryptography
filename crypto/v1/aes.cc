#include "crypto/v1/aes.h"
#include "crypto/v1/errors.h"
#include "crypto/v1/mem.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <string.h>

size_t AES_get_encrypted_size(SIZE inlen)
{
	return inlen + AES_BLOCK_SIZE;
}

size_t AES_get_decrypted_size(SIZE inlen)
{
	return inlen;
}

int AES_encrypt_init(ENCRYPT_CONTEXT encr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
	BYTES key_data, iv_data;

	allocate_memory(&key_data, 64);
	allocate_memory(&iv_data, 64);

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key, keylen, rounds, key_data, iv_data) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	if (EVP_CIPHER_CTX_init(encr) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_EncryptInit_ex(encr, EVP_aes_256_cbc(), NULL, key_data, iv_data) <= 0)
	{
		return EVP_EncryptInit_ex_ERROR;
	}

	free_memory(key_data, iv_data);

	return 1;
}

int AES_decrypt_init(DECRYPT_CONTEXT decr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
	BYTES key_data, iv_data;

	allocate_memory(&key_data, 64);
	allocate_memory(&iv_data, 64);

	if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key, keylen, rounds, key_data, iv_data) != 32)
	{
		return EVP_BytesToKey_ERROR;
	}

	if (EVP_CIPHER_CTX_init(decr) <= 0)
	{
		return EVP_CIPHER_CTX_init_ERROR;
	}

	if (EVP_DecryptInit_ex(decr, EVP_aes_256_cbc(), NULL, key_data, iv_data) <= 0)
	{
		return EVP_DecryptInit_ex_ERROR;
	}

	free_memory(key_data, iv_data);

	return 1;
}

int AES_init(ENCRYPT_CONTEXT encr, DECRYPT_CONTEXT decr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
	int result = AES_encrypt_init(encr, key, keylen, salt, rounds);

	if (result < 0)
	{
		return result;
	}

	return AES_decrypt_init(decr, key, keylen, salt, rounds);
}

ENCRYPT_CONTEXT AES_create_encrypt_ctx(BYTES key, SIZE keylen, BYTES salt, int rounds)
{
	ENCRYPT_CONTEXT ctx = EVP_CIPHER_CTX_new();
	AES_encrypt_init(ctx, key, keylen, salt, rounds);

	return ctx;
}

DECRYPT_CONTEXT AES_create_decrypt_ctx(BYTES key, SIZE keylen, BYTES salt, int rounds)
{
	DECRYPT_CONTEXT ctx = EVP_CIPHER_CTX_new();
	AES_decrypt_init(ctx, key, keylen, salt, rounds);

	return ctx;
}

void AES_free_context(CIPHER_CONTEXT ctx)
{
	EVP_CIPHER_CTX_free(ctx);
}

int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
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
	out[outlen] = 0;

	return 1;
}

int AES_decrypt(DECRYPT_CONTEXT decr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
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
	out[outlen] = 0;

	return 1;
}
