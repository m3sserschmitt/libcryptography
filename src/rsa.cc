/*
MIT License

Copyright (c) 2020 Romulus-Emanuel Ruja (romulus-emanuel.ruja@tutanota.com).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
 * Rivest–Shamir–Adleman (RSA) encryption / decryption implementation with Openssl
 * cryptographic library. This files contains method for public & private keys
 * creation, encryption & decryption.
*/

#include "../include/cryptography.h"

#include <openssl/pem.h>
#include <string.h>

EVP_PKEY *Cryptography::create_private_RSA(std::string key)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	const char *c_string = key.c_str();
	BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

EVP_PKEY *Cryptography::create_public_RSA(std::string key)
{
	RSA *rsa = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	BIO *keybio;
	const char *c_string = key.c_str();
	
	keybio = BIO_new_mem_buf((void *)c_string, -1);

	if (keybio == NULL)
	{
		return 0;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	return pkey;
}

std::string Cryptography::get_public_PEM(EVP_PKEY *key) {
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(keybio, key);
	
	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);
	
	return (*bufferPtr).data;
}

std::string Cryptography::get_private_PEM(EVP_PKEY *key) {
	BIO *keybio = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(keybio, EVP_PKEY_get1_RSA(key), nullptr, nullptr, 0, nullptr, nullptr);
	
	BUF_MEM *bufferPtr;
	BIO_get_mem_ptr(keybio, &bufferPtr);
	
	return (*bufferPtr).data;
}

int Cryptography::RSA_sign(EVP_PKEY *privKey, const unsigned char *Msg, size_t MsgLen, unsigned char *EncMsg, size_t &MsgLenEnc)
{
	EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
	
	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, privKey) <= 0)
	{
		return EVP_DigestSignInit_ERROR;
	}
	
	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
	{
		return EVP_DigestSignUpdate_ERROR;
	}
	
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, &MsgLenEnc) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}
	
	if (EVP_DigestSignFinal(m_RSASignCtx, EncMsg, &MsgLenEnc) <= 0)
	{
		return EVP_DigestSignFinal_ERROR;
	}
	
	EVP_MD_CTX_free(m_RSASignCtx);
	
	return 1;
}

int Cryptography::RSA_sign(EVP_PKEY *private_key, std::string plainText, char *signature)
{
	size_t outlen = Cryptography::get_RSA_size(private_key);
	unsigned char *encMessage = (unsigned char *) malloc(outlen + 1);
	memset(encMessage, 0, outlen + 1);

	bool result = RSA_sign(private_key, (unsigned char *)plainText.c_str(), plainText.length(), encMessage, outlen);
	
    if(result <= 0) {
        return result;
    }
	
	strcpy(signature, base64_encode(encMessage, outlen).data());

	return result;
}

int Cryptography::RSA_verify_signature(EVP_PKEY *pubKey, unsigned char *MsgHash, size_t MsgHashLen, const char *Msg, size_t MsgLen, bool &Authentic)
{
	Authentic = false;

	EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();
		if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
	{
		return EVP_DigestVerifyInit_ERROR;
	}
	
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
	{
		return EVP_DigestVerifyUpdate_ERROR;
	}
	
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	
	if (AuthStatus == 1)
	{
		Authentic = true;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else if (AuthStatus == 0)
	{
		Authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else
	{
		Authentic = false;
		EVP_MD_CTX_free(m_RSAVerifyCtx);
		return EVP_DigestVerifyFinal_ERROR;
	}
}

int Cryptography::RSA_verify_signature(EVP_PKEY *publicKey, std::string plainText, char *signatureBase64, bool &authentic)
{
	size_t encMessageLength;
	unsigned char *encMessage = base64_decode(signatureBase64, encMessageLength);

	int result = RSA_verify_signature(publicKey, encMessage, encMessageLength, plainText.c_str(), plainText.length(), authentic);
	free(encMessage);
	
	return result;
}

int Cryptography::get_RSA_size(EVP_PKEY *key) {
	return EVP_PKEY_size(key);
}

int Cryptography::get_RSA_encoded_size(EVP_PKEY *key) {
	return get_encode_length(get_RSA_size(key));
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
	int result = RSA_encrypt(in, inlen, (unsigned char *) out, outlen, key);

	if (result < 0)
	{
		return result;
	}

	strcpy(out, base64_encode((unsigned char *)out, outlen).data());

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
	unsigned char *decoded = base64_decode(in, decoded_length);

	int result = RSA_decrypt(decoded, decoded_length, out, outlen, key);
	free(decoded);

	return result;
}