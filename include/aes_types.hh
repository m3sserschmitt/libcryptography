#ifndef AES_TYPES_HH
#define AES_TYPES_HH

#include "types.hh"

#include <openssl/evp.h>

struct _AES_CRYPTO
{
    BYTES key;
    // single IV used AES_encrypt & AES_decrypt functions;
    [[deprecated("It might be removed in further releases;")]] BYTES iv;

    // distinct contexts are used for encryption & decryption
    EVP_CIPHER_CTX *encr;
    EVP_CIPHER_CTX *decr;

    // track context initialization for encryption & decryption
    [[deprecated("It might be removed in further releases;")]]bool encrinit;
    [[deprecated("It might be removed in further releases;")]]bool decrinit;

    [[deprecated("It might be removed in further releases;")]] bool iv_autoset;
    [[deprecated("It might be removed in further releases;")]] bool iv_append;

    _AES_CRYPTO *ref;
};

#endif
