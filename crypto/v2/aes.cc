#include "crypto/v2/aes.h"
#include "crypto/v1/mem.h"

#include <cstring>

int AES_encrypt_init(ENCRYPT_CONTEXT *encr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
    *encr = EVP_CIPHER_CTX_new();
    return AES_encrypt_init(*encr, key, keylen, salt, rounds);
}

int AES_decrypt_init(DECRYPT_CONTEXT *decr, BYTES key, SIZE keylen, BYTES salt, int rounds)
{
    *decr = EVP_CIPHER_CTX_new();
    return AES_decrypt_init(*decr, key, keylen, salt, rounds);
}

int AES_init(ENCRYPT_CONTEXT *encr, DECRYPT_CONTEXT *decr, BYTES key, SIZE keylen, BYTES salt, int rounds)
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

int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    
    allocate_memory(out, AES_get_encrypted_size(inlen) + 1);
    return AES_encrypt(encr, in, inlen, *out, outlen);
}

int AES_decrypt(DECRYPT_CONTEXT decr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen)
{
    allocate_memory(out, AES_get_decrypted_size(inlen) + 1);
    return AES_decrypt(decr, in, inlen, *out, outlen);
}