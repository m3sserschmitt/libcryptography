#include "aes.hh"

#include <openssl/aes.h>
#include <openssl/evp.h>

static inline SIZE AES_get_encrypted_size(SIZE inlen)
{
    return inlen + AES_BLOCK_SIZE;
}

AES_CRYPTO AES_CRYPTO_new()
{
    return new _AES_CRYPTO;
}

int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx)
{
    if (not ctx->key or not ctx->iv)
    {
        ctx->key = (BYTES)calloc(64, sizeof(BYTE));
        ctx->iv = (BYTES)calloc(64, sizeof(BYTE));

        if (not ctx->key or not ctx->iv or EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, passphrase, passlen, rounds, ctx->key, ctx->iv) != 32)
        {
            return -1;
        }
    }

    EVP_CIPHER_CTX **aes = 0;

    op == ENCRYPT and (aes = (EVP_CIPHER_CTX **)&ctx->encr);
    op == DECRYPT and (aes = (EVP_CIPHER_CTX **)&ctx->decr);

    if (not(*aes = EVP_CIPHER_CTX_new()))
    {
        return -1;
    }

    if (EVP_CIPHER_CTX_init(*aes) <= 0)
    {
        return -1;
    }

    return 0;
}

int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, AES_CRYPTO ctx)
{
    return AES_init(passphrase, passlen, salt, rounds, ENCRYPT, ctx) == 0 and AES_init(passphrase, passlen, salt, rounds, DECRYPT, ctx) == 0 ? 0 : -1;
}

int AES_encrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = AES_get_encrypted_size(inlen);
    int f_len = 0;

    /* allows reusing of 'e' for multiple encryption cycles */
    if (EVP_EncryptInit_ex((EVP_CIPHER_CTX *)ctx->encr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv) <= 0)
    {
        return -1;
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
    *out or (*out = (BYTES)calloc(c_len + 1, sizeof(BYTE)));
    if (not *out or EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->encr, *out, &c_len, in, inlen) <= 0)
    {
        return -1;
    }

    /* update ciphertext with the final remaining bytes */
    if (EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)ctx->encr, *out + c_len, &f_len) <= 0)
    {
        return -1;
    }

    EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)ctx->encr);

    SIZE outlen = c_len + f_len;
    (*out)[outlen] = 0;

    return outlen;
}

int AES_decrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out)
{
    int delta = inlen % AES_BLOCK_SIZE;
    (delta < 8 and (inlen -= delta)) or (inlen += AES_BLOCK_SIZE - delta);

    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = inlen, f_len = 0;

    if (EVP_DecryptInit_ex((EVP_CIPHER_CTX *)ctx->decr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv) <= 0)
    {
        return -1;
    }

    *out or (*out = (BYTES)calloc(p_len + 1, sizeof(BYTE)));
    if (not *out or EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->decr, *out, &p_len, in, inlen) <= 0)
    {
        return -1;
    }

    if (EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)ctx->decr, *out + p_len, &f_len) <= 0)
    {
        return -1;
    }

    EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX *)ctx->decr);

    SIZE outlen = p_len + f_len;
    (*out)[outlen] = 0;

    return outlen;
}
