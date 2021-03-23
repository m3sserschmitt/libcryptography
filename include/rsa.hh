#ifndef RSA_HH
#define RSA_HH

#include "types.hh"

#include <string>
#include <openssl/pem.h>

enum KEY_TYPE
{
    PUBLIC_KEY = 0,
    PRIVATE_KEY = 1
};

RSA_CRYPTO RSA_CRYPTO_new();

int RSA_init_key(std::string PEM, pem_password_cb *cb, BYTES passphrase, KEY_TYPE ktype, RSA_CRYPTO ctx);

int RSA_init_ctx(RSA_CRYPTO ctx, CRYPTO_OP op);

int RSA_sign(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *sign);

int RSA_verify(RSA_CRYPTO ctx, BYTES sign, SIZE signlen, BYTES data, SIZE datalen, bool &auth);

int RSA_encrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);

int RSA_decrypt(RSA_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);

#endif
