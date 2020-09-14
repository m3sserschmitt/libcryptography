#include "../../include/v3/aes.h"

#include <cstring>

int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BASE64 *out)
{
    size_t required_memory = get_AES_encoded_size(inlen) + 1;
    *out = (char *)malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_encrypt(encr, in, inlen, *out);
}

int AES_decrypt(DECRYPT_CTX decr, BASE64 in, BYTES *out, SIZE &outlen)
{
    size_t required_memory = get_AES_decoded_size(strlen(in)) + 1;
    *out = (unsigned char *)malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_decrypt(decr, in, *out, outlen);
}