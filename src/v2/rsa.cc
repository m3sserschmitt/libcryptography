#include "../../include/v2/rsa.h"
#include "../../include/v1/base64.h"

#include <string.h>

int get_RSA_encoded_size(EVP_PKEY *key)
{
	return get_encoded_length(get_RSA_size(key));
}

int RSA_sign(EVP_PKEY *private_key, unsigned char *in, size_t inlen, char *signature)
{
	size_t outlen = get_RSA_encoded_size(private_key) + 1;
	unsigned char *encMessage = (unsigned char *)malloc(outlen);
	memset(encMessage, 0, outlen);

	int result = RSA_sign(private_key, (unsigned char *)in, inlen, encMessage, outlen);

	if (result < 0)
	{
		return result;
	}

	base64_encode(encMessage, outlen, signature);

	// strcpy(signature, base64_encode(encMessage, outlen).data());

	return result;
}

int RSA_verify_signature(EVP_PKEY *publicKey, unsigned char *in, size_t inlen, char *signatureBase64, bool &authentic)
{
	size_t encMessageLength;
	unsigned char *encMessage = (unsigned char *)malloc(get_RSA_size(publicKey));
	// printf("checkpoint0\n");
	base64_decode(signatureBase64, encMessage, encMessageLength);
	// printf("checkpoint1\n");
	int result = RSA_verify_signature(publicKey, encMessage, encMessageLength, in, inlen, authentic);
	free(encMessage);
	// printf("checkpoint2\n");
	return result;
}

int RSA_encrypt(unsigned char *in, size_t inlen, char *out, EVP_PKEY *key)
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

int RSA_decrypt(char *in, unsigned char *out, size_t &outlen, EVP_PKEY *key)
{
	size_t decoded_length;
	// unsigned char *decoded = base64_decode(in, decoded_length);
	unsigned char *decoded = (unsigned char *)malloc(get_decoded_length(in));
	base64_decode(in, decoded, decoded_length);

	int result = RSA_decrypt(decoded, decoded_length, out, outlen, key);
	free(decoded);

	return result;
}