#include "crypto/v2/rsa.h"
#include "crypto/v1/mem.h"

#include <cstring>

int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *signature, SIZE &signlen)
{
    allocate_memory(signature, ctx->maxlen);
    return RSA_sign(ctx, in, inlen, *signature, signlen);
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES *signature, SIZE &signlen)
{
    allocate_memory(signature, RSA_get_size(key) + 1);
    return RSA_sign(key, in, inlen, *signature, signlen);
}

int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    allocate_memory(out, ctx->maxlen + 1);
    return RSA_encrypt(ctx, in, inlen, *out, outlen);
}

int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    allocate_memory(out, RSA_get_size(key) + 1);
    return RSA_encrypt(key, in, inlen, *out, outlen);
}

int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    allocate_memory(out, ctx->maxlen);
    return RSA_decrypt(ctx, in, inlen, *out, outlen);
}

int RSA_decrypt(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    allocate_memory(out, RSA_get_size(key) + 1);
    return RSA_decrypt(key, in, inlen, *out, outlen);
}
