#include "../../include/v3/rsa.h"
#include "../../include/v2/base64.h"

#include <cstring>

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 *signature)
{
    SIZE signlen;
    BYTES sign_buffer;
    int result = RSA_sign(key, in, inlen, &sign_buffer, signlen);

    if (result < 0)
    {
        free(sign_buffer);
        return result;
    }

    base64_encode(sign_buffer, signlen, signature);
    free(sign_buffer);

    return result;
}

int RSA_encrypt(BYTES in, SIZE inlen, BASE64 *out, PUBLIC_KEY key)
{
    SIZE outlen;
    BYTES out_buffer;
    int result = RSA_encrypt(in, inlen, &out_buffer, outlen, key);

    if (result < 0)
    {
        free(out_buffer);
        return result;
    }

    base64_encode(out_buffer, outlen, out);
    free(out_buffer);

    return result;
}

int RSA_decrypt(BASE64 in, BYTES *out, SIZE &outlen, PRIVATE_KEY key)
{
    SIZE inlen;
    BYTES in_buffer;

    base64_decode(in, &in_buffer, inlen);

    int result = RSA_decrypt(in_buffer, inlen, out, outlen, key);
    free(in_buffer);

    return result;
}