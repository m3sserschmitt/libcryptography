#include "cryptography/rsa.hh"
#include "cryptography/base64.hh"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <math.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <string.h>

using namespace std;

struct _RSA_CRYPTO
{
	EVP_PKEY *pubkey;
	EVP_PKEY *privkey;
	EVP_MD_CTX *sign;
	EVP_MD_CTX *verif;
	EVP_PKEY_CTX *encr;
	EVP_PKEY_CTX *decr;
	bool pubkeyinit;
	bool privkeyinit;
	bool signinit;
	bool verifinit;
	bool encrinit;
	bool decrinit;
};

static size_t get_rsa_size(size_t inlen)
{
	size_t p = log(inlen) / log(2);

	size_t m = pow(2, p);
	size_t l = pow(2, p - 1);
	size_t n = pow(2, p + 1);

	if (m == inlen)
	{
		return inlen;
	}
	else if (m - l > n - m)
	{
		return n;
	}
	else
	{
		return l;
	}
}

RSA_CRYPTO CRYPTO::RSA_CRYPTO_new()
{
	_RSA_CRYPTO *ctx = new _RSA_CRYPTO;

	ctx->pubkey = 0;
	ctx->privkey = 0;
	ctx->sign = 0;
	ctx->verif = 0;
	ctx->encr = 0;
	ctx->decr = 0;
	ctx->pubkeyinit = 0;
	ctx->privkeyinit = 0;
	ctx->signinit = 0;
	ctx->verifinit = 0;
	ctx->encrinit = 0;
	ctx->decrinit = 0;

	return ctx;
}

int CRYPTO::RSA_generate_keys(const string &public_key, const string &private_key, SIZE bits, bool encrypt_key, BYTE *passphrase, SIZE passlen, password_cb *cb)
{
	unsigned long e = RSA_F4;
	BIGNUM *bignum = BN_new();

	if (BN_set_word(bignum, e) != 1)
	{
		BN_free(bignum);

		return -1;
	}

	RSA *r = RSA_new();
	if (RSA_generate_key_ex(r, bits, bignum, 0) != 1)
	{
		BN_free(bignum);
		RSA_free(r);

		return -1;
	}

	BIO *pub = BIO_new_file(public_key.c_str(), "w+");
	if (PEM_write_bio_RSA_PUBKEY(pub, r) != 1)
	{
		BN_free(bignum);
		RSA_free(r);
		BIO_free_all(pub);

		return -1;
	}

	BIO *priv = BIO_new_file(private_key.c_str(), "w+");
	const EVP_CIPHER *cipher = 0;

	if (encrypt_key)
	{
		cipher = EVP_aes_256_cbc();
	}

	if (PEM_write_bio_RSAPrivateKey(priv, r, cipher, passphrase, passlen, cb, 0) != 1)
	{
		BN_free(bignum);
		RSA_free(r);
		BIO_free_all(pub);
		BIO_free_all(priv);

		return -1;
	}

	BN_free(bignum);
	RSA_free(r);
	BIO_free_all(pub);
	BIO_free_all(priv);

	return 0;
}

int CRYPTO::RSA_init_key(const string &PEM, password_cb *cb, BYTE *passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx)
{
	if (not ctx)
	{
		return -1;
	}

	if ((ktype == PUBLIC_KEY and ctx->pubkeyinit) or (ktype == PRIVATE_KEY and ctx->privkeyinit))
	{
		return 0;
	}

	BIO *keybio = 0;

	if (not(keybio = BIO_new_mem_buf((void *)PEM.c_str(), -1)))
	{
		return -1;
	}

	typedef RSA *(*PEM_read_key)(BIO *, RSA **, password_cb *, void *);

	EVP_PKEY **key = 0;
	PEM_read_key pem_read_key = 0;

	ktype == PRIVATE_KEY and (pem_read_key = PEM_read_bio_RSAPrivateKey) and (key = &ctx->privkey);
	ktype == PUBLIC_KEY and (pem_read_key = PEM_read_bio_RSA_PUBKEY) and (key = &ctx->pubkey);

	RSA *rsa = 0;

	if (not(rsa = pem_read_key(keybio, &rsa, cb, passphrase)))
	{
		BIO_free(keybio);

		return -1;
	}

	if (not(*key = EVP_PKEY_new()))
	{
		return -1;
	}

	if (not EVP_PKEY_assign_RSA(*key, rsa))
	{
		return -1;
	}

	ktype == PUBLIC_KEY and (ctx->pubkeyinit = 1);
	ktype == PRIVATE_KEY and (ctx->privkeyinit = 1);

	BIO_free(keybio);

	return 0;
}

int CRYPTO::RSA_init_key_file(const std::string &filename, password_cb *cb, BYTE *passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx)
{
	if (not ctx)
	{
		return -1;
	}

	if ((ktype == PUBLIC_KEY and ctx->pubkeyinit) or (ktype == PRIVATE_KEY and ctx->privkeyinit))
	{
		return 0;
	}

	FILE *file = fopen(filename.c_str(), "rb");

	if (not file)
	{
		return -1;
	}

	RSA *rsa = 0;

	if (ktype == PRIVATE_KEY)
	{
		if (not(rsa = PEM_read_RSAPrivateKey(file, &rsa, cb, passphrase)))
		{
			return -1;
		}

		if (not(ctx->privkey = EVP_PKEY_new()))
		{
			return -1;
		}

		if (not EVP_PKEY_assign_RSA(ctx->privkey, rsa))
		{
			return -1;
		}

		ctx->privkeyinit = 1;
	}
	else if (ktype == PUBLIC_KEY)
	{
		if (not(rsa = PEM_read_RSA_PUBKEY(file, &rsa, cb, passphrase)))
		{
			return -1;
		}

		if (not(ctx->pubkey = EVP_PKEY_new()))
		{
			return -1;
		}

		if (not EVP_PKEY_assign_RSA(ctx->pubkey, rsa))
		{
			return -1;
		}

		ctx->pubkeyinit = 1;
	}

	fclose(file);

	return 0;
}

int CRYPTO::RSA_pubkey_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->pubkeyinit;
}

int CRYPTO::RSA_privkey_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->privkeyinit;
}

// int CRYPTO::PEM_key_to_DER(RSA_CRYPTO ctx, BYTES *der)
// {
// 	if (not ctx or not ctx->pubkey)
// 	{
// 		return -1;
// 	}

// 	return i2d_PUBKEY(ctx->pubkey, der);
// }

int CRYPTO::RSA_init_ctx(RSA_CRYPTO ctx, CRYPTO_OP op)
{
	if (not ctx)
	{
		return -1;
	}

	if ((op == SIGN and not ctx->signinit) or (op == VERIFY and not ctx->verifinit))
	{
		EVP_MD_CTX **op_ctx = 0;

		op == SIGN and (op_ctx = &ctx->sign);
		op == VERIFY and (op_ctx = &ctx->verif);

		if (not(*op_ctx = EVP_MD_CTX_create()))
		{
			return -1;
		}

		op == SIGN and (ctx->signinit = 1);
		op == VERIFY and (ctx->verifinit = 1);
	}
	else if((op == ENCRYPT and not ctx->encrinit) or (op == DECRYPT and not ctx->decrinit))
	{
		typedef int (*Crypto_init)(EVP_PKEY_CTX *);

		EVP_PKEY_CTX **op_ctx = 0;
		Crypto_init crypto_init;

		if (op == ENCRYPT)
		{
			ctx->encr = EVP_PKEY_CTX_new(ctx->pubkey, 0);
			crypto_init = EVP_PKEY_encrypt_init;
			op_ctx = &ctx->encr;
		}
		else
		{
			ctx->decr = EVP_PKEY_CTX_new(ctx->privkey, 0);
			crypto_init = EVP_PKEY_decrypt_init;
			op_ctx = &ctx->decr;
		}

		if (not *op_ctx)
		{
			return -1;
		}

		if (crypto_init(*op_ctx) <= 0)
		{
			return -1;
		}

		op == ENCRYPT and (ctx->encrinit = 1);
		op == DECRYPT and (ctx->decrinit = 1);
	}

	return 0;
}

int CRYPTO::RSA_encrypt_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->encrinit;
}

int CRYPTO::RSA_decrypt_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->decrinit;
}

int CRYPTO::RSA_sign_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->signinit;
}

int CRYPTO::RSA_verify_ready(const _RSA_CRYPTO *ctx)
{
	return ctx->verifinit;
}

int CRYPTO::RSA_sign(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *sign)
{
	if (not ctx)
	{
		return -1;
	}

	if(not ctx->signinit)
	{
		return -1;
	}

	SIZE signlen;

	if (EVP_DigestSignInit(ctx->sign, 0, EVP_sha256(), 0, (EVP_PKEY *)ctx->privkey) <= 0)
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

	*sign or (*sign = new BYTE[signlen + 1]);

	if (not *sign)
	{
		return -1;
	}

	memset(*sign, 0, signlen + 1);

	if (not *sign or EVP_DigestSignFinal(ctx->sign, *sign, &signlen) <= 0)
	{
		return -1;
	}

	EVP_MD_CTX_reset(ctx->sign);

	return signlen;
}

int CRYPTO::RSA_verify(RSA_CRYPTO ctx, const BYTE *sign, SIZE signlen, const BYTE *data, SIZE datalen, bool &auth)
{
	if (not ctx)
	{
		return -1;
	}

	if(not ctx->verifinit)
	{
		return -1;
	}

	signlen = get_rsa_size(signlen);
	auth = false;

	if (EVP_DigestVerifyInit(ctx->verif, 0, EVP_sha256(), 0, (EVP_PKEY *)ctx->pubkey) <= 0)
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

int CRYPTO::RSA_encrypt(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out)
{
	if (not ctx)
	{
		return -1;
	}

	if(not ctx->encrinit)
	{
		return -1;
	}

	SIZE outlen;

	if (EVP_PKEY_encrypt(ctx->encr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = new BYTE[outlen + 1]);

	if (not *out)
	{
		return -1;
	}

	memset(*out, 0, outlen + 1);

	if (EVP_PKEY_encrypt(ctx->encr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}

int CRYPTO::RSA_decrypt(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out)
{
	if (not ctx)
	{
		return -1;
	}

	if(not ctx->decrinit)
	{
		return -1;
	}

	inlen = get_rsa_size(inlen);
	SIZE outlen;

	if (EVP_PKEY_decrypt(ctx->decr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = new BYTE[outlen + 1]);

	if (not *out)
	{
		return -1;
	}

	memset(*out, 0, outlen + 1);

	if (EVP_PKEY_decrypt(ctx->decr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}

void CRYPTO::RSA_CRYPTO_free(RSA_CRYPTO ctx)
{
	if (not ctx)
	{
		return;
	}

	if (ctx->pubkey)
	{
		EVP_PKEY_free(ctx->pubkey);
	}

	if (ctx->privkey)
	{
		EVP_PKEY_free(ctx->privkey);
	}

	if (ctx->encr)
	{
		EVP_PKEY_CTX_free(ctx->encr);
	}

	if (ctx->decr)
	{
		EVP_PKEY_CTX_free(ctx->decr);
	}

	if (ctx->sign)
	{
		EVP_MD_CTX_free(ctx->sign);
	}

	if (ctx->verif)
	{
		EVP_MD_CTX_free(ctx->verif);
	}
}
