
/*
 * Advanced Encryption Standard (AES) encryption / decryption with OpenSSL 
 * cryptographic library. This file contains methods for ciphers 
 * initialization, encryption and decryption.
 */

#include "../include/cryptography.h"


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
	
	base64_encode((unsigned char *) out, outlen, out);
    // strcpy(out, base64_encode((unsigned char *) out, outlen).data());
    
	return result;
}

int Cryptography::AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char *out, size_t &outlen)
{
	size_t decoded_length;
	unsigned char *decoded = (unsigned char *) malloc(get_decode_length(in));

	base64_decode(in, decoded, decoded_length);
	// unsigned char *decoded = base64_decode(in, decoded_length);

	int result = AES_decrypt(decrypt_ctx, decoded, decoded_length, out, outlen);
	free(decoded);

	return result;
}