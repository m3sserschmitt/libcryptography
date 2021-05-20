#ifndef TYPES_HH
#define TYPES_HH

#include <cstddef>
#include <openssl/evp.h>

enum CRYPTO_OP
{
    ENCRYPT = 0,
    DECRYPT = 1,
    SIGN = 2,
    VERIFY = 3
};

typedef size_t SIZE;

typedef unsigned char BYTE;

typedef BYTE *BYTES;

typedef char *PLAINTEXT;

typedef PLAINTEXT BASE64;



typedef EVP_CIPHER_CTX *AES_CTX;

typedef struct {
    // BYTES passphrase;
    // SIZE passlen;
    BYTES key;
    SIZE keylen;
    BYTES iv;
    // SIZE ivlen;
    AES_CTX encr;
    AES_CTX decr;
} _AES_CRYPTO;

typedef _AES_CRYPTO *AES_CRYPTO; 


typedef EVP_PKEY *KEY;

typedef EVP_MD_CTX *SIGN_CTX;

typedef EVP_PKEY_CTX *PKEY_CTX;

typedef struct {
    KEY pubkey;
    KEY privkey;
    SIGN_CTX sign;
    SIGN_CTX verif;
    PKEY_CTX encr;
    PKEY_CTX decr;
} _RSA_CRYPTO;

typedef _RSA_CRYPTO *RSA_CRYPTO;

#endif