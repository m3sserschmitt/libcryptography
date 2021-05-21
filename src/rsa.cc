#include "rsa.hh"

#include <math.h>
#include <string>
#include <openssl/evp.h>

using namespace std;

RSA_CRYPTO RSA_CRYPTO_new()
{
	return new _RSA_CRYPTO;
}

int RSA_init_key(string PEM, pem_password_cb *cb, BYTES passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx)
{
	typedef RSA *(*PEM_read_key)(BIO *, RSA **, pem_password_cb *, void *);

	BIO *keybio = 0;
	RSA *rsa = 0;

	PEM_read_key pem_read_key = 0;
	KEY *key = 0;

	if (not(keybio = BIO_new_mem_buf((void *)PEM.c_str(), -1)))
	{
		return -1;
	}

	ktype == PRIVATE_KEY and (pem_read_key = PEM_read_bio_RSAPrivateKey) and (key = &ctx->privkey);
	ktype == PUBLIC_KEY and (pem_read_key = PEM_read_bio_RSA_PUBKEY) and (key = &ctx->pubkey);

	if (not(rsa = pem_read_key(keybio, &rsa, cb, passphrase)))
	{
		return -1;
	}

	*key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(*key, rsa);

	return 0;
}

int RSA_init_ctx(RSA_CRYPTO ctx, CRYPTO_OP op)
{
	if (op == SIGN or op == VERIFY)
	{
		SIGN_CTX *op_ctx = 0;

		op == SIGN and (op_ctx = &ctx->sign);
		op == VERIFY and (op_ctx = &ctx->verif);

		if (not(*op_ctx = EVP_MD_CTX_create()))
		{
			return -1;
		}
	}
	else
	{
		PKEY_CTX op_ctx = 0;

		typedef int (*Crypto_init)(EVP_PKEY_CTX *);
		Crypto_init crypto_init;

		if (op == ENCRYPT)
		{
			ctx->encr = EVP_PKEY_CTX_new(ctx->pubkey, 0);
			crypto_init = EVP_PKEY_encrypt_init;
			op_ctx = ctx->encr;
		}
		else
		{
			ctx->decr = EVP_PKEY_CTX_new(ctx->privkey, 0);
			crypto_init = EVP_PKEY_decrypt_init;
			op_ctx = ctx->decr;
		}

		if (not op_ctx)
		{
			return -1;
		}

		if (crypto_init(op_ctx) <= 0)
		{
			return -1;
		}
	}

	return 0;
	/*
	SIGN_CTX *signctx = 0;

	ktype == PRIVATE_KEY and (signctx = &ctx->sign);
	ktype == PUBLIC_KEY and (signctx = &ctx->verif);

	if (not *signctx and not (*signctx = EVP_MD_CTX_create()))
	{
		return -1;
	}
*/
}

int RSA_sign(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *sign)
{
	SIZE signlen;

	if (EVP_DigestSignInit(ctx->sign, 0, EVP_sha256(), 0, ctx->privkey) <= 0)
	{
		return -1;
	}

	if (EVP_DigestSignUpdate(ctx->sign, in, inlen) <= 0)
	{
		return -1;
	}

	if (EVP_DigestSignFinal(ctx->sign, 0, &signlen) <= 0)
	{
		return -1;
	}

	*sign or (*sign = (BYTES)calloc(signlen + 1, sizeof(BYTE)));

	if (not *sign or EVP_DigestSignFinal(ctx->sign, *sign, &signlen) <= 0)
	{
		return -1;
	}

	EVP_MD_CTX_reset(ctx->sign);

	return signlen;
}

static size_t get_rsa_size(size_t inlen)
{
	size_t p = log(inlen) / log(2);
	size_t m = pow(2, p);
	size_t delta = inlen % m;

	if(not delta)
	{
		return inlen;
	}

    (delta < m / 2 and (inlen -= delta)) or (inlen += m - delta);

	return inlen;
}

int RSA_verify(RSA_CRYPTO ctx, BYTES sign, SIZE signlen, BYTES data, SIZE datalen, bool &auth)
{
	signlen = get_rsa_size(signlen) - 1;
	auth = false;

	if (EVP_DigestVerifyInit(ctx->verif, 0, EVP_sha256(), 0, ctx->pubkey) <= 0)
	{
		return -1;
	}

	if (EVP_DigestVerifyUpdate(ctx->verif, data, datalen) <= 0)
	{
		return -1;
	}

	int AuthStatus = EVP_DigestVerifyFinal(ctx->verif, sign, signlen);

	EVP_MD_CTX_reset(ctx->verif);

	if (AuthStatus == 1)
	{
		auth = true;
		return 0;
	}
	else if (AuthStatus == 0)
	{
		auth = false;
		return 0;
	}
	else
	{
		auth = false;
		return -1;
	}
}

int RSA_encrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
	SIZE outlen;

	if (EVP_PKEY_encrypt(ctx->encr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = (BYTES)calloc(outlen + 1, sizeof(BYTE)));

	if (EVP_PKEY_encrypt(ctx->encr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}

int RSA_decrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
	inlen = get_rsa_size(inlen) - 1;
	SIZE outlen;

	if (EVP_PKEY_decrypt(ctx->decr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = (BYTES)calloc(outlen + 1, sizeof(BYTE)));

	if (EVP_PKEY_decrypt(ctx->decr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}
