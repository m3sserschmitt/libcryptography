/**
 * @file types.hh
 * @author Romulus-Emanuel Ruja
 * @brief This file contain some type definitions.
 * @version 0.1
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */


#ifndef TYPES_HH
#define TYPES_HH

#include <cstddef>

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

typedef struct {
    BYTES key;
    SIZE keylen;
    BYTES iv;
    void *encr;
    void *decr;
} _AES_CRYPTO;

typedef _AES_CRYPTO *AES_CRYPTO; 

typedef struct {
    void *pubkey;
    void *privkey;
    void *sign;
    void *verif;
    void *encr;
    void *decr;
} _RSA_CRYPTO;

enum KEY_TYPE
{
    PUBLIC_KEY = 0,
    PRIVATE_KEY = 1
};

typedef _RSA_CRYPTO *RSA_CRYPTO;

#endif
