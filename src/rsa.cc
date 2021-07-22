#include "rsa.hh"
#include "base64.hh"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <math.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <string.h>

using namespace std;

struct _RSA_CRYPTO {
    EVP_PKEY *pubkey;
    EVP_PKEY *privkey;
    EVP_MD_CTX *sign;
    EVP_MD_CTX *verif;
    EVP_PKEY_CTX *encr;
    EVP_PKEY_CTX *decr;
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

RSA_CRYPTO RSA_CRYPTO_new()
{
	_RSA_CRYPTO *ctx = new _RSA_CRYPTO;

	ctx->pubkey = 0;
    ctx->privkey = 0;
    ctx->sign = 0;
    ctx->verif = 0;
    ctx->encr = 0;
    ctx->decr = 0;

	return ctx;
}

int RSA_generate_keys(string public_key, string private_key, SIZE bits, bool encrypt_key, BYTES passphrase, SIZE passlen, password_cb *cb)
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

int RSA_init_key(string PEM, password_cb *cb, BYTES passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx)
{
	typedef RSA *(*PEM_read_key)(BIO *, RSA **, password_cb *, void *);

	BIO *keybio = 0;
	RSA *rsa = 0;

	PEM_read_key pem_read_key = 0;
	EVP_PKEY **key = 0;

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

int RSA_init_key_file(std::string filename, password_cb *cb, BYTES passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx)
{
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

		ctx->privkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(ctx->privkey, rsa);
	}
	else if (ktype == PUBLIC_KEY)
	{
		if (not(rsa = PEM_read_RSA_PUBKEY(file, &rsa, cb, passphrase)))
		{
			return -1;
		}

		ctx->pubkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(ctx->pubkey, rsa);
	}

	fclose(file);

	return 0;
}

int PEM_key_to_DER(RSA_CRYPTO ctx, BYTES *der)
{
	if (not ctx or not ctx->pubkey)
	{
		return -1;
	}

	return i2d_PUBKEY(ctx->pubkey, der);
}

int RSA_init_ctx(RSA_CRYPTO ctx, CRYPTO_OP op)
{
	if (op == SIGN or op == VERIFY)
	{
		EVP_MD_CTX **op_ctx = 0;

		op == SIGN and (op_ctx = &ctx->sign);
		op == VERIFY and (op_ctx = &ctx->verif);

		if (not(*op_ctx = EVP_MD_CTX_create()))
		{
			return -1;
		}
	}
	else
	{
		EVP_PKEY_CTX **op_ctx = 0;

		typedef int (*Crypto_init)(EVP_PKEY_CTX *);
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

		if (not op_ctx)
		{
			return -1;
		}

		if (crypto_init(*op_ctx) <= 0)
		{
			return -1;
		}
	}

	return 0;
}

int RSA_sign(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *sign)
{
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

	if (not *sign or EVP_DigestSignFinal(ctx->sign, *sign, &signlen) <= 0)
	{
		return -1;
	}

	EVP_MD_CTX_reset(ctx->sign);

	return signlen;
}

int RSA_verify(RSA_CRYPTO ctx, BYTES sign, SIZE signlen, BYTES data, SIZE datalen, bool &auth)
{
	signlen = get_rsa_size(signlen);
	auth = false;

	if (EVP_DigestVerifyInit((EVP_MD_CTX *)ctx->verif, 0, EVP_sha256(), 0, (EVP_PKEY *)ctx->pubkey) <= 0)
	{
		return -1;
	}

	if (EVP_DigestVerifyUpdate((EVP_MD_CTX *)ctx->verif, data, datalen) <= 0)
	{
		return -1;
	}

	int AuthStatus = EVP_DigestVerifyFinal((EVP_MD_CTX *)ctx->verif, sign, signlen);

	EVP_MD_CTX_reset((EVP_MD_CTX *)ctx->verif);

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

	*out or (*out = new BYTE[outlen + 1]);

	if (EVP_PKEY_encrypt(ctx->encr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}

int RSA_decrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
	inlen = get_rsa_size(inlen);
	SIZE outlen;

	if (EVP_PKEY_decrypt(ctx->decr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = new BYTE[outlen + 1]);

	if (EVP_PKEY_decrypt(ctx->decr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}
