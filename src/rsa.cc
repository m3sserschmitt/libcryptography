#include "rsa.hh"
#include "base64.hh"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <math.h>
#include <string>
#include <vector>

using namespace std;

static vector<string> split(string str, string sep, int max_split)
{
	vector<string> tokens;

	size_t sep_pos;
	int split_index = 0;

	if (!str.size())
		return tokens;

	tokens.reserve(10);

	do
	{
		split_index++;
		sep_pos = str.find(sep);

		// tokens.resize(tokens.size() + 1);
		tokens.push_back(str.substr(0, sep_pos));
		if (sep_pos == string::npos)
		{
			// tokens.resize(split_index);
			return tokens;
		}

		str = str.substr(sep_pos + sep.size());
		if (split_index == max_split && str.size())
		{

			// tokens.resize(tokens.size() + 1);
			tokens.push_back(str);
			// tokens.resize(split_index + 1);
			return tokens;
		}
	} while (true);

	return tokens;
}

RSA_CRYPTO RSA_CRYPTO_new()
{
	return new _RSA_CRYPTO;
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

	ktype == PRIVATE_KEY and (pem_read_key = PEM_read_bio_RSAPrivateKey) and (key = (EVP_PKEY **)&ctx->privkey);
	ktype == PUBLIC_KEY and (pem_read_key = PEM_read_bio_RSA_PUBKEY) and (key = (EVP_PKEY **)&ctx->pubkey);

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
		EVP_MD_CTX **op_ctx = 0;

		op == SIGN and (op_ctx = (EVP_MD_CTX **)&ctx->sign);
		op == VERIFY and (op_ctx = (EVP_MD_CTX **)&ctx->verif);

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
			ctx->encr = EVP_PKEY_CTX_new((EVP_PKEY *)ctx->pubkey, 0);
			crypto_init = EVP_PKEY_encrypt_init;
			op_ctx = (EVP_PKEY_CTX **)&ctx->encr;
		}
		else
		{
			ctx->decr = EVP_PKEY_CTX_new((EVP_PKEY *)ctx->privkey, 0);
			crypto_init = EVP_PKEY_decrypt_init;
			op_ctx = (EVP_PKEY_CTX **)&ctx->decr;
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

int PEM_key_to_DER(string PEM, BYTES *out)
{
	vector<string> tokens = split(PEM, "\n", -1);
	vector<string>::iterator it = tokens.begin() + 1;
	vector<string>::iterator it_end = tokens.end() - 1;

	string base64_key;

	for (; it != it_end; it++)
	{
		base64_key += *it;
	}

	return base64_decode((BASE64)base64_key.data(), out);
}

int RSA_sign(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *sign)
{
	SIZE signlen;

	if (EVP_DigestSignInit((EVP_MD_CTX *)ctx->sign, 0, EVP_sha256(), 0, (EVP_PKEY *)ctx->privkey) <= 0)
	{
		return -1;
	}

	if (EVP_DigestSignUpdate((EVP_MD_CTX *)ctx->sign, in, inlen) <= 0)
	{
		return -1;
	}

	if (EVP_DigestSignFinal((EVP_MD_CTX *)ctx->sign, 0, &signlen) <= 0)
	{
		return -1;
	}

	*sign or (*sign = (BYTES)calloc(signlen + 1, sizeof(BYTE)));

	if (not *sign or EVP_DigestSignFinal((EVP_MD_CTX *)ctx->sign, *sign, &signlen) <= 0)
	{
		return -1;
	}

	EVP_MD_CTX_reset((EVP_MD_CTX *)ctx->sign);

	return signlen;
}

static size_t get_rsa_size(size_t inlen)
{
	size_t p = log(inlen) / log(2);
	
	size_t m = pow(2, p);
	size_t l = pow(2, p - 1);
	size_t n = pow(2, p + 1);

	if(m = inlen)
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
	/*size_t delta = inlen % m;

	if(not delta)
	{
		return inlen;
	}

    (delta < m / 2 and (inlen -= delta)) or (inlen += m - delta);

		return inlen;
	*/
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

	if (EVP_PKEY_encrypt((EVP_PKEY_CTX *)ctx->encr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = (BYTES)calloc(outlen + 1, sizeof(BYTE)));

	if (EVP_PKEY_encrypt((EVP_PKEY_CTX *)ctx->encr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}

int RSA_decrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
	inlen = get_rsa_size(inlen);
	SIZE outlen;

	if (EVP_PKEY_decrypt((EVP_PKEY_CTX *)ctx->decr, 0, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	*out or (*out = (BYTES)calloc(outlen + 1, sizeof(BYTE)));

	if (EVP_PKEY_decrypt((EVP_PKEY_CTX *)ctx->decr, *out, &outlen, in, inlen) <= 0)
	{
		return -1;
	}

	return outlen;
}
