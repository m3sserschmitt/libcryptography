#ifndef AES_HH
#define AES_HH

#include "types.hh"

AES_CRYPTO AES_CRYPTO_new();

int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx);

int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, AES_CRYPTO ctx);

int AES_encrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);

int AES_decrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);

#endif
