#include "../../include/v2/aes.h"

#include <cstring>

int AES_encrypt_init(ENCRYPT_CTX *encr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
    *encr = EVP_CIPHER_CTX_new();
    return AES_encrypt_init(*encr, key, keylen, salt, rounds);
}

int AES_decrypt_init(DECRYPT_CTX *decr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
    *decr = EVP_CIPHER_CTX_new();
    return AES_decrypt_init(*decr, key, keylen, salt, rounds);
}

int AES_init(BYTES key, SIZE keylen, BYTES salt, int rounds, ENCRYPT_CTX *encr, DECRYPT_CTX *decr)
{
    *encr = EVP_CIPHER_CTX_new();
    *decr = EVP_CIPHER_CTX_new();

    int result = AES_encrypt_init(*encr, key, keylen, salt, rounds);

    if (result < 0)
    {
        return result;
    }

    return AES_decrypt_init(*decr, key, keylen, salt, rounds);
}

int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    SIZE required_memory = get_AES_encrypted_size(inlen) + 1;
    *out = (BYTES) malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_encrypt(encr, in, inlen, *out, outlen);
}

int AES_decrypt(DECRYPT_CTX decr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    SIZE required_memory = get_AES_decrypted_size(inlen) + 1;
    *out = (BYTES) malloc(required_memory);
    memset(*out, 0, required_memory);

    return AES_decrypt(decr, in, inlen, *out, outlen);
}