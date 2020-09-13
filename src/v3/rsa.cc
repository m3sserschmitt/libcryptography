#include "../../include/v3/rsa.h"

#include <cstring>

int RSA_sign(EVP_PKEY *private_key, unsigned char *in, size_t inlen, char **signature) {
    size_t required_memory = get_RSA_encoded_size(private_key);
    *signature = (char *) malloc(required_memory);
    memset(*signature, 0, required_memory);

    return RSA_sign(private_key, in, inlen, *signature);
}

int RSA_encrypt(unsigned char *in, size_t inlen, char **out, EVP_PKEY *public_key) {
    size_t required_memory = get_RSA_encoded_size(public_key);
    *out = (char *) malloc(required_memory);
    memset(*out, 0, required_memory);

    return RSA_encrypt(in, inlen, *out, public_key);
}

int RSA_decrypt(char *in, unsigned char **out, size_t &outlen, EVP_PKEY *private_key) {
    size_t required_memory = get_RSA_size(private_key);
    *out = (unsigned char *) malloc(required_memory);
    memset(*out, 0, required_memory);

    return RSA_decrypt(in, *out, outlen, private_key);
}