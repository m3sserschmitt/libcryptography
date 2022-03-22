/**
 * @file types.hh
 * @author Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>
 * @brief This file contain some type definitions.
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

typedef char CHAR;

typedef CHAR *PLAINTEXT;

typedef PLAINTEXT BASE64;

struct _AES_CRYPTO;

typedef _AES_CRYPTO *AES_CRYPTO; 

enum KEY_TYPE
{
    PUBLIC_KEY = 0,
    PRIVATE_KEY = 1
};

struct _RSA_CRYPTO;
typedef _RSA_CRYPTO *RSA_CRYPTO;

#endif
