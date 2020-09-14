#include "../../include/v2/rsa.h"
#include "../../include/v2/base64.h"

#include <string.h>

int get_RSA_encoded_size(KEY key)
{
	return get_encoded_length(get_RSA_size(key));
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 signature)
{
	size_t outlen;
	int result = RSA_sign(key, in, inlen, (unsigned char *) signature, outlen);

	if (result < 0)
	{
		return result;
	}

	base64_encode((unsigned char *)signature, outlen, signature);

	return result;
}

int RSA_verify_signature(PUBLIC_KEY key, BYTES in, SIZE inlen, BASE64 signature, bool &authentic)
{
	size_t encMessageLength;
	unsigned char *encMessage;
	
	base64_decode(signature, &encMessage, encMessageLength);
	
	int result = RSA_verify_signature(key, encMessage, encMessageLength, in, inlen, authentic);
	
	free(encMessage);
	
	return result;
}

int RSA_encrypt(BYTES in, SIZE inlen, BASE64 out, PUBLIC_KEY key)
{
	size_t outlen;
	int result = RSA_encrypt(in, inlen, (unsigned char *)out, outlen, key);

	if (result < 0)
	{
		return result;
	}

	base64_encode((unsigned char *)out, outlen, out);

	return result;
}

int RSA_decrypt(BASE64 in, BYTES out, SIZE &outlen, PRIVATE_KEY key)
{
	size_t decoded_length;
	unsigned char *decoded;
	base64_decode(in, &decoded, decoded_length);
	
	int result = RSA_decrypt(decoded, decoded_length, out, outlen, key);
	
	free(decoded);

	return result;
}