#include "aes.hh"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>

struct _AES_CRYPTO
{
    BYTES key;
    BYTES iv;
    EVP_CIPHER_CTX *encr;
    EVP_CIPHER_CTX *decr;
    bool encrinit;
    bool decrinit;
};

static inline SIZE AES_get_encrypted_size(SIZE inlen)
{
    return inlen + AES_BLOCK_SIZE;
}

AES_CRYPTO AES_CRYPTO_new()
{
    _AES_CRYPTO *ctx = new _AES_CRYPTO;

    ctx->key = 0;
    ctx->iv = 0;
    ctx->encr = 0;
    ctx->decr = 0;
    ctx->encrinit = 0;
    ctx->decrinit = 0;

    return ctx;
}

int AES_setup_key(BYTES key, AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return -1;
    }

    SIZE keylen = 0;

    ctx->encr and (keylen = EVP_CIPHER_CTX_key_length(ctx->encr));
    ctx->decr and (keylen = EVP_CIPHER_CTX_key_length(ctx->decr));

    if (not keylen)
    {
        return -1;
    }

    ctx->key or (ctx->key = new BYTE[keylen + 1]);

    if (not ctx->key)
    {
        return -1;
    }

    memset(ctx->key, 0, keylen + 1);
    memcpy(ctx->key, key, keylen);

    return 0;
}

int AES_setup_iv(BYTES iv, AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return -1;
    }

    SIZE ivlen = 0;

    ctx->encr and (ivlen = EVP_CIPHER_CTX_iv_length(ctx->encr));
    ctx->decr and (ivlen = EVP_CIPHER_CTX_iv_length(ctx->decr));

    if (not ivlen)
    {
        return -1;
    }

    ctx->iv or (ctx->iv = new BYTE[ivlen + 1]);

    if (not ctx->iv)
    {
        return -1;
    }

    memset(ctx->iv, 0, ivlen + 1);
    memcpy(ctx->iv, iv, ivlen);

    return 0;
}

int AES_get_key(AES_CRYPTO ctx, BYTES *key)
{
    SIZE keylen = 0;

    ctx->encr and (keylen = EVP_CIPHER_CTX_key_length(ctx->encr));
    ctx->decr and (keylen = EVP_CIPHER_CTX_key_length(ctx->decr));

    if (not keylen)
    {
        return -1;
    }

    *key or (*key = new BYTE[keylen + 1]);

    if (not *key)
    {
        return -1;
    }

    memset(key, 0, keylen + 1);
    memcpy(*key, ctx->key, keylen);

    return keylen;
}

int AES_get_iv(AES_CRYPTO ctx, BYTES *iv)
{
    SIZE ivlen = 0;

    ctx->encr and (ivlen = EVP_CIPHER_CTX_iv_length(ctx->encr));
    ctx->decr and (ivlen = EVP_CIPHER_CTX_iv_length(ctx->decr));

    if (not ivlen)
    {
        return -1;
    }

    *iv or (*iv = new BYTE[ivlen + 1]);

    if (not *iv)
    {
        return -1;
    }

    memset(iv, 0, ivlen + 1);
    memcpy(*iv, ctx->iv, ivlen);

    return ivlen;
}

int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx)
{
    if (passphrase and passlen and ctx)
    {
        ctx->key or (ctx->key = new BYTE[32 + 1]);
        ctx->iv or (ctx->iv = new BYTE[16 + 1]);

        if (not ctx->key or not ctx->iv)
        {
            return -1;
        }

        memset(ctx->key, 0, 32 + 1);
        memset(ctx->iv, 0, 16 + 1);

        if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, passphrase, passlen, rounds, ctx->key, ctx->iv) != 32)
        {
            return -1;
        }
    }

    EVP_CIPHER_CTX **aes = 0;

    op == ENCRYPT and (aes = &ctx->encr);
    op == DECRYPT and (aes = &ctx->decr);

    if (not(*aes or (*aes = EVP_CIPHER_CTX_new())))
    {
        return -1;
    }

    if ((op == ENCRYPT and not ctx->encrinit) or (op == DECRYPT and not ctx->decrinit))
    {
        if (EVP_CIPHER_CTX_init(*aes) <= 0)
        {
            return -1;
        }

        op == ENCRYPT and (ctx->encrinit = 1);
        op == DECRYPT and (ctx->decrinit = 1);
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
    if (EVP_EncryptInit_ex(ctx->encr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv) <= 0)
    {
        return -1;
    }

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
    *out or (*out = new BYTE[c_len + 1]);
    if (not *out or EVP_EncryptUpdate(ctx->encr, *out, &c_len, in, inlen) <= 0)
    {
        return -1;
    }

    /* update ciphertext with the final remaining bytes */
    if (EVP_EncryptFinal_ex(ctx->encr, *out + c_len, &f_len) <= 0)
    {
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(ctx->encr);

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

    if (EVP_DecryptInit_ex(ctx->decr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv) <= 0)
    {
        return -1;
    }

    *out or (*out = new BYTE[p_len + 1]);
    if (not *out or EVP_DecryptUpdate(ctx->decr, *out, &p_len, in, inlen) <= 0)
    {
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx->decr, *out + p_len, &f_len) <= 0)
    {
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(ctx->decr);

    SIZE outlen = p_len + f_len;
    (*out)[outlen] = 0;

    return outlen;
}
