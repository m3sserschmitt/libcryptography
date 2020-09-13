#include "../../include/v3/aes.h"

#include <cstring>

int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, char **out)
{
    size_t required_memory = get_AES_encoded_size(inlen);
    *out = (char *)malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_encrypt(encrypt_ctx, in, inlen, *out);
}

int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char **out, size_t &outlen) {
    size_t required_memory = get_AES_decoded_size(strlen(in));
    *out = (unsigned char *)malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_decrypt(decrypt_ctx, in, *out, outlen);
}