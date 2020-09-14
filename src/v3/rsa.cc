#include "../../include/v3/rsa.h"

#include <cstring>

int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 *signature)
{
    size_t required_memory = get_RSA_encoded_size(key) + 1;
    *signature = (char *)malloc(required_memory);
    memset(*signature, 0, required_memory);

    return RSA_sign(key, in, inlen, *signature);
}

int RSA_encrypt(BYTES in, SIZE inlen, BASE64 *out, PUBLIC_KEY key)
{
    size_t required_memory = get_RSA_encoded_size(key) + 1;
    *out = (char *)malloc(required_memory);
    memset(*out, 0, required_memory);

    return RSA_encrypt(in, inlen, *out, key);
}

int RSA_decrypt(BASE64 in, BYTES *out, SIZE &outlen, PRIVATE_KEY key)
{
    size_t required_memory = get_RSA_size(key) + 1;
    *out = (unsigned char *)malloc(required_memory);
    memset(*out, 0, required_memory);
    
    return RSA_decrypt(in, *out, outlen, key);
}