/*
MIT License

Copyright (c) 2020 Romulus-Emanuel Ruja (romulus-emanuel.ruja@tutanota.com).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
 * Advanced Encryption Standard (AES) encryption / decryption with OpenSSL 
 * cryptographic library. This file contains methods for ciphers 
 * initialization, encryption and decryption.
 */

#include "../include/cryptography.h"

#include <openssl/aes.h>
#include <string.h>

size_t Cryptography::get_AES_encrypted_size(size_t plaintext_size) {
	return plaintext_size + AES_BLOCK_SIZE;
}

size_t Cryptography::get_AES_decrypted_size(size_t ciphertext_size) {
	return ciphertext_size - AES_BLOCK_SIZE;
}

size_t Cryptography::get_AES_encrypted_encoded_size(size_t plaintext_size) {
	return get_encode_length(get_AES_encrypted_size(plaintext_size));
}

size_t Cryptography::get_AES_decrypted_decoded_size(size_t ciphercode_size) {
	return get_AES_decrypted_size(get_decode_length(ciphercode_size));
}

int Cryptography::AES_cipher_key_init(unsigned char *key_data, int key_data_len, unsigned char *salt, unsigned int rounds, unsigned char *key, unsigned char *iv) {
	int result = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, rounds, key, iv);
	
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
// 	int i, nrounds = 5;
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

	result = AES_decrypt_init(d_ctx, key, iv);

	return result;
	return 1;
}

int Cryptography::AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen)
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

int Cryptography::AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen)
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

int Cryptography::AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, char *out)
{
	size_t outlen;
	int result = AES_encrypt(encrypt_ctx, in, inlen, (unsigned char *) out, outlen);

	if (result < 0)
	{
		return result;
	}
	
    strcpy(out, base64_encode((unsigned char *) out, outlen).data());
    
	return result;
}

int Cryptography::AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char *out, size_t &outlen)
{
	size_t decoded_length;
	unsigned char *decoded = base64_decode(in, decoded_length);

	int result = AES_decrypt(decrypt_ctx, decoded, decoded_length, out, outlen);
	free(decoded);

	return result;
}