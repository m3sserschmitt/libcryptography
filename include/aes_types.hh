#ifndef AES_TYPES_HH
#define AES_TYPES_HH

#include "types.hh"

#include <openssl/evp.h>

struct _AES_CRYPTO
{
    BYTES key;
    BYTES iv;
    EVP_CIPHER_CTX *encr;
    EVP_CIPHER_CTX *decr;
    bool encrinit;
    bool decrinit;
    bool iv_autoset;
    bool iv_append;

    _AES_CRYPTO *ref;
};

#endif
