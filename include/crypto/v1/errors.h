/**
 * \file errors.h
 * \brief Error codes.
*/

#define EVP_PKEY_new_ERROR -1
#define EVP_PKEY_assign_RSA_ERROR -2
#define EVP_PKEY_CTX_new_ERROR -3
#define EVP_PKEY_encrypt_init_ERROR -4
#define EVP_PKEY_encrypt_ERROR -5
#define EVP_PKEY_decrypt_init_ERROR -6
#define EVP_PKEY_decrypt_ERROR -7
#define OPENSSL_malloc_ERROR -8

#define EVP_BytesToKey_ERROR -9
#define EVP_CIPHER_CTX_init_ERROR -10
#define EVP_EncryptInit_ex_ERROR -11
#define EVP_DecryptInit_ex_ERROR -12
#define EVP_EncryptUpdate_ERROR -13
#define EVP_EncryptFinal_ex_ERROR -14
#define EVP_DecryptUpdate_ERROR -15
#define EVP_DecryptFinal_ex_ERROR -16

#define EVP_DigestVerifyInit_ERROR -17 
#define EVP_DigestVerifyUpdate_ERROR -18
#define EVP_DigestVerifyFinal_ERROR -19

#define EVP_DigestSignInit_ERROR -20
#define EVP_DigestSignUpdate_ERROR -21
#define EVP_DigestSignFinal_ERROR -22