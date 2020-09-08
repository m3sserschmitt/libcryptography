#include "../include/cryptography.h"


int Cryptography::RSA_sign(EVP_PKEY *privKey, unsigned char *Msg, size_t MsgLen, unsigned char *EncMsg, size_t &MsgLenEnc)
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

int Cryptography::RSA_sign(EVP_PKEY *private_key, char *plainText, char *signature)
{
	size_t outlen = Cryptography::get_RSA_size(private_key);
	unsigned char *encMessage = (unsigned char *)malloc(outlen + 1);
	memset(encMessage, 0, outlen + 1);

	bool result = RSA_sign(private_key, (unsigned char *)plainText, strlen(plainText), encMessage, outlen);

	if (result <= 0)
	{
		return result;
	}

	base64_encode(encMessage, outlen, signature);

	// strcpy(signature, base64_encode(encMessage, outlen).data());

	return result;
}

int Cryptography::RSA_verify_signature(EVP_PKEY *pubKey, unsigned char *MsgHash, size_t MsgHashLen, unsigned char *Msg, size_t MsgLen, bool &Authentic)
{
	Authentic = false;

	EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();
	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
	{
		return EVP_DigestVerifyInit_ERROR;
	}
	// printf("checkpoint1\n");
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
	{
		return EVP_DigestVerifyUpdate_ERROR;
	}
	// printf("checkpoint2\n");
	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
	// printf("checkpoint3\n");
	if (AuthStatus == 1)
	{
		// printf("checkpoint4\n");
		Authentic = true;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		// printf("checkpoint4.5\n");
		return 1;
	}
	else if (AuthStatus == 0)
	{
		// printf("checkpoint5\n");
		Authentic = false;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		return 1;
	}
	else
	{
		// printf("checkpoint6\n");
		Authentic = false;
		// EVP_MD_CTX_free(m_RSAVerifyCtx);
		return EVP_DigestVerifyFinal_ERROR;
	}
}

int Cryptography::RSA_verify_signature(EVP_PKEY *publicKey, char *plainText, char *signatureBase64, bool &authentic)
{
	size_t encMessageLength;
	unsigned char *encMessage = (unsigned char *)malloc(get_RSA_size(publicKey));
	// printf("checkpoint0\n");
	base64_decode(signatureBase64, encMessage, encMessageLength);
	// printf("checkpoint1\n");
	int result = RSA_verify_signature(publicKey, encMessage, encMessageLength, (unsigned char *) plainText, strlen(plainText), authentic);
	free(encMessage);
	// printf("checkpoint2\n");
	return result;
}