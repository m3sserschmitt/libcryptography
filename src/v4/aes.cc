#include "../../include/v4/aes.h"
#include "../../include/v2/base64.h"

#include <cstring>

int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BASE64 *out)
{
    SIZE outlen;
    BYTES out_buffer;
    int result = AES_encrypt(encr, in, inlen, &out_buffer, outlen);

    if (result < 0)
    {
        free(out_buffer);
        return result;
    }

    base64_encode(out_buffer, outlen, out);
    free(out_buffer);

    return result;
}

int AES_decrypt(DECRYPT_CTX decr, BASE64 in, BYTES *out, SIZE &outlen)
{
    SIZE inlen;
    BYTES in_buffer;

    base64_decode(in, &in_buffer, inlen);

    int result = AES_decrypt(decr, in_buffer, inlen, out, outlen);
    free(in_buffer);

    return result;
}