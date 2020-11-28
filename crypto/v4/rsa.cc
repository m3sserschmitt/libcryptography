#include "crypto/v4/rsa.h"
#include "crypto/v2/base64.h"

#include <cstring>

int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BASE64 *signature)
{
    SIZE signlen;
    BYTES sign_buffer;
    int result = RSA_sign(ctx, in, inlen, &sign_buffer, signlen);

    if (result < 0)
    {
        free(sign_buffer);
        return result;
    }

    base64_encode(sign_buffer, signlen, signature);
    free(sign_buffer);

    return result;
}

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 *signature)
{
    SIGN_CONTEXT ctx = RSA_create_sign_ctx(key);
    int result = RSA_sign(ctx, in, inlen, signature);
    RSA_free_sign_ctx(ctx);
    
    return result;
}

int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BASE64 *out)
{
    SIZE outlen;
    BYTES out_buffer;
    int result = RSA_encrypt(ctx, in, inlen, &out_buffer, outlen);

    if (result < 0)
    {
        free(out_buffer);
        return result;
    }

    base64_encode(out_buffer, outlen, out);
    free(out_buffer);

    return result;
}

int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BASE64 *out)
{
    RSA_ENCRYPT_CONTEXT ctx = RSA_create_encrypt_ctx(key);
    int result = RSA_encrypt(ctx, in, inlen, out);
    RSA_free_context(ctx);

    return result;
}

int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BASE64 in, BYTES *out, SIZE &outlen) {
    SIZE inlen;
    BYTES in_buffer;

    base64_decode(in, &in_buffer, inlen);

    int result = RSA_decrypt(ctx, in_buffer, inlen, out, outlen);
    free(in_buffer);

    return result;
}

int RSA_decrypt(PRIVATE_KEY key, BASE64 in, BYTES *out, SIZE &outlen)
{
    RSA_DECRYPT_CONTEXT ctx = RSA_create_decrypt_ctx(key);
    int result = RSA_decrypt(ctx, in, out, outlen);
    RSA_free_context(ctx);

    return result;
}