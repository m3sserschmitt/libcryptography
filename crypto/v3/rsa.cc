#include "crypto/v3/rsa.h"
#include "crypto/v2/base64.h"
#include "crypto/v1/mem.h"

#include <string.h>

int RSA_get_encoded_size(KEY key)
{
	return base64_get_encoded_length(RSA_get_size(key));
}

int RSA_get_encoded_size(SIGN_CONTEXT ctx)
{
	return base64_get_encoded_length(ctx->maxlen);
}

int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BASE64 signature)
{
	SIZE outlen;
	int result = RSA_sign(ctx, in, inlen, (BYTES)signature, outlen);

	if (result < 0)
	{
		return result;
	}

	base64_encode((BYTES)signature, outlen, signature);

	return result;
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 signature)
{
	SIGN_CONTEXT ctx = RSA_create_sign_ctx(key);
	int result = RSA_sign(ctx, in, inlen, signature);
	RSA_free_sign_ctx(ctx);

	return result;
}

int RSA_verify_signature(VERIFY_CONTEXT ctx, BYTES in, SIZE inlen, BASE64 signature, bool &authentic)
{
	SIZE encMessageLength;
	BYTES encMessage;

	base64_decode(signature, &encMessage, encMessageLength);

	int result = RSA_verify_signature(ctx, encMessage, encMessageLength, in, inlen, authentic);

	free_memory(encMessage);

	return result;
}

int RSA_verify_signature(PUBLIC_KEY key, BYTES in, SIZE inlen, BASE64 signature, bool &authentic)
{
	VERIFY_CONTEXT ctx = RSA_create_verify_ctx(key);
	int result = RSA_verify_signature(ctx, in, inlen, signature, authentic);
	RSA_free_verify_ctx(ctx);

	return result;
}

int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BASE64 out)
{
	SIZE outlen;
	int result = RSA_encrypt(ctx, in, inlen, (BYTES)out, outlen);

	if (result < 0)
	{
		return result;
	}

	base64_encode((BYTES)out, outlen, out);

	return result;
}

int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BASE64 out)
{
	RSA_ENCRYPT_CONTEXT ctx = RSA_create_encrypt_ctx(key);
	int result = RSA_encrypt(ctx, in, inlen, out);
	RSA_free_context(ctx);

	return result;
}

int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BASE64 in, BYTES out, SIZE &outlen)
{
	SIZE decoded_length;
	BYTES decoded;
	base64_decode(in, &decoded, decoded_length);

	int result = RSA_decrypt(ctx, decoded, decoded_length, out, outlen);

	free_memory(decoded);

	return result;
}

int RSA_decrypt(PRIVATE_KEY key, BASE64 in, BYTES out, SIZE &outlen)
{
	RSA_DECRYPT_CONTEXT ctx = RSA_create_decrypt_ctx(key);
	int result = RSA_decrypt(ctx, in, out, outlen);
	RSA_free_context(ctx);

	return result;
}