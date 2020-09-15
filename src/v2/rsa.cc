#include "../../include/v2/rsa.h"

#include <cstring>

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES *signature, SIZE &signlen)
{
    SIZE required_memory = get_RSA_size(key) + 1;
    *signature = (BYTES)malloc(required_memory);
    memset(*signature, 0, required_memory);

    return RSA_sign(key, in, inlen, *signature, signlen);
}

int RSA_encrypt(BYTES in, SIZE inlen, BYTES *out, SIZE &outlen, PUBLIC_KEY key)
{
    SIZE required_memory = get_RSA_size(key) + 1;
    *out = (BYTES)malloc(required_memory);
    memset(*out, 0, required_memory);

    return RSA_encrypt(in, inlen, *out, outlen, key);
}

int RSA_decrypt(BYTES in, SIZE inlen, BYTES *out, SIZE &outlen, PRIVATE_KEY key)
{
    SIZE required_memory = get_RSA_size(key) + 1;
    *out = (BYTES)malloc(required_memory);
    memset(*out, 0, required_memory);

    return RSA_decrypt(in, inlen, *out, outlen, key);
}
