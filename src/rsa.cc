

/*
 * Rivest–Shamir–Adleman (RSA) encryption / decryption implementation with Openssl
 * cryptographic library. This files contains method for public & private keys
 * creation, encryption & decryption.
*/

#include "../include/cryptography.h"


int Cryptography::get_RSA_encoded_size(EVP_PKEY *key)
{
	return get_encode_length(get_RSA_size(key));
}

int Cryptography::get_RSA_size(EVP_PKEY *key)
{
	return EVP_PKEY_size(key);
}

int Cryptography::RSA_encrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *pub_key)
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

int Cryptography::RSA_encrypt(unsigned char *in, size_t inlen, char *out, EVP_PKEY *key)
{
	size_t outlen;
	int result = RSA_encrypt(in, inlen, (unsigned char *)out, outlen, key);

	if (result < 0)
	{
		return result;
	}

	base64_encode((unsigned char *)out, outlen, out);
	// strcpy(out, base64_encode((unsigned char *)out, outlen).data());

	return result;
}

int Cryptography::RSA_decrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *priv_key)
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

int Cryptography::RSA_decrypt(char *in, unsigned char *out, size_t &outlen, EVP_PKEY *key)
{
	size_t decoded_length;
	// unsigned char *decoded = base64_decode(in, decoded_length);
	unsigned char *decoded = (unsigned char *)malloc(get_decode_length(in));
	base64_decode(in, decoded, decoded_length);

	int result = RSA_decrypt(decoded, decoded_length, out, outlen, key);
	free(decoded);

	return result;
}