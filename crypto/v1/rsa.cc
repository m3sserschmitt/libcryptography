#include "crypto/v1/rsa.h"
#include "crypto/v1/errors.h"
#include "crypto/v1/mem.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

int RSA_get_size(KEY key)
{
	return EVP_PKEY_size(key);
}

PRIVATE_KEY RSA_create_private_key(string key_pem)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	const char *c_string = key_pem.c_str();
	BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

PUBLIC_KEY RSA_create_public_key(string key_pem)
{
	// printf("checkpoint1\n");
	// printf("%s", key_pem.c_str());
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	BIO *keybio;
	const char *c_string = key_pem.c_str();
	// printf("checkpoint2\n");
	keybio = BIO_new_mem_buf((void *)c_string, -1);
	// printf("checkpoint3\n");
	if (keybio == NULL)
	{
		return 0;
	}
	// printf("checkpoint4\n");
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	// printf("checkpoint5\n");
	EVP_PKEY_assign_RSA(pkey, rsa);
	// printf("checkpoint6\n");
	return pkey;
}

SIGN_CONTEXT RSA_create_sign_ctx(PRIVATE_KEY key)
{
	MD_CONTEXT sgn_ctx = EVP_MD_CTX_create();

	if (not sgn_ctx)
	{
		return nullptr;
	}

	if (EVP_DigestSignInit(sgn_ctx, NULL, EVP_sha256(), NULL, key) <= 0)
	{
		EVP_MD_CTX_free(sgn_ctx);
		return nullptr;
	}

	SIGN_CONTEXT ctx = (SIGN_CONTEXT)malloc(sizeof(SIGN_CONTEXT));
	ctx->maxlen = EVP_PKEY_size(key);
	ctx->bits = ctx->maxlen * 8;
	ctx->sign_ctx = sgn_ctx;

	return ctx;
}

VERIFY_CONTEXT RSA_create_verify_ctx(PUBLIC_KEY key)
{
	VERIFY_CONTEXT ctx = EVP_MD_CTX_create();

	if (not ctx)
	{
		return nullptr;
	}

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0)
	{
		EVP_MD_CTX_free(ctx);
		return nullptr;
	}

	return ctx;
}

RSA_ENCRYPT_CONTEXT RSA_create_encrypt_ctx(PUBLIC_KEY key)
{
	PKEY_CONTEXT encr_ctx = EVP_PKEY_CTX_new(key, NULL);

	if (not encr_ctx)
	{
		return nullptr;
	}

	if (EVP_PKEY_encrypt_init(encr_ctx) <= 0)
	{
		EVP_PKEY_CTX_free(encr_ctx);
		return nullptr;
	}

	RSA_ENCRYPT_CONTEXT ctx = (RSA_ENCRYPT_CONTEXT)malloc(sizeof(RSA_ENCRYPT_CONTEXT));
	ctx->ctx = encr_ctx;
	ctx->maxlen = RSA_get_size(key);
	ctx->bits = ctx->maxlen * 8;

	return ctx;
}

RSA_DECRYPT_CONTEXT RSA_create_decrypt_ctx(PRIVATE_KEY key)
{
	PKEY_CONTEXT decr_ctx = EVP_PKEY_CTX_new(key, NULL);

	if (not decr_ctx)
	{
		return nullptr;
	}

	if (EVP_PKEY_decrypt_init(decr_ctx) <= 0)
	{
		EVP_PKEY_CTX_free(decr_ctx);
		return nullptr;
	}

	RSA_DECRYPT_CONTEXT ctx = (RSA_DECRYPT_CONTEXT)malloc(sizeof(RSA_DECRYPT_CONTEXT));
	ctx->ctx = decr_ctx;
	ctx->maxlen = RSA_get_size(key);
	ctx->bits = ctx->maxlen * 8;

	return ctx;
}

void RSA_free_key(KEY key)
{
	EVP_PKEY_free(key);
}

void RSA_free_sign_ctx(SIGN_CONTEXT ctx)
{
	EVP_MD_CTX_free(ctx->sign_ctx);
	free_memory(ctx);
}

void RSA_free_verify_ctx(VERIFY_CONTEXT ctx)
{
	EVP_MD_CTX_free(ctx);
}

void RSA_free_context(RSA_PKEY_CONTEXT ctx)
{
	EVP_PKEY_CTX_free(ctx->ctx);
	free_memory(ctx);
}

string RSA_get_public_PEM(PUBLIC_KEY key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(keybio, key);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

string RSA_get_private_PEM(PRIVATE_KEY key)
{
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(keybio, EVP_PKEY_get1_RSA(key), nullptr, nullptr, 0, nullptr, nullptr);

	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);

	return (*bufferPtr).data;
}

int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen)
{
	if (EVP_DigestSignUpdate(ctx->sign_ctx, in, inlen) <= 0)
	{
		return EVP_DigestSignUpdate_ERROR;
	}

	if (EVP_DigestSignFinal(ctx->sign_ctx, NULL, &signlen) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	if (EVP_DigestSignFinal(ctx->sign_ctx, signature, &signlen) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}

	return 1;
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen)
{
	SIGN_CONTEXT ctx = RSA_create_sign_ctx(key);

	int result = RSA_sign(ctx, in, inlen, signature, signlen);

	RSA_free_sign_ctx(ctx);

	return result;
}

int RSA_verify_signature(VERIFY_CONTEXT ctx, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic)
{
	authentic = false;

	if (EVP_DigestVerifyUpdate(ctx, data, datalen) <= 0)
	{
		return EVP_DigestVerifyUpdate_ERROR;
	}

	int AuthStatus = EVP_DigestVerifyFinal(ctx, hash, hashlen);

	if (AuthStatus == 1)
	{
		authentic = true;
		return 1;
	}
	else if (AuthStatus == 0)
	{
		authentic = false;
		return 1;
	}
	else
	{
		authentic = false;
		return EVP_DigestVerifyFinal_ERROR;
	}
}

int RSA_verify_signature(PUBLIC_KEY key, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic)
{
	authentic = false;

	VERIFY_CONTEXT ctx = RSA_create_verify_ctx(key);

	int result = RSA_verify_signature(ctx, hash, hashlen, data, datalen, authentic);

	RSA_free_verify_ctx(ctx);

	return result;
}

int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	if (EVP_PKEY_encrypt(ctx->ctx, NULL, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_encrypt_ERROR;
	}

	if (EVP_PKEY_encrypt(ctx->ctx, out, &outlen, in, inlen) < 0)
	{
		return EVP_PKEY_encrypt_ERROR;
	}

	return 1;
}

int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	RSA_ENCRYPT_CONTEXT ctx = RSA_create_encrypt_ctx(key);

	int result = RSA_encrypt(ctx, in, inlen, out, outlen);

	RSA_free_context(ctx);

	return result;
}

int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	if (EVP_PKEY_decrypt(ctx->ctx, NULL, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_decrypt_ERROR;
	}
	if (EVP_PKEY_decrypt(ctx->ctx, out, &outlen, in, inlen) <= 0)
	{
		return EVP_PKEY_decrypt_ERROR;
	}

	return 1;
}

int RSA_decrypt(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES out, SIZE &outlen)
{
	RSA_DECRYPT_CONTEXT ctx = RSA_create_decrypt_ctx(key);

	int result = RSA_decrypt(ctx, in, inlen, out, outlen);

	RSA_free_context(ctx);

	return result;
}