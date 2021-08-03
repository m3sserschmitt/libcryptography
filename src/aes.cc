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

AES_CRYPTO CRYPTO::AES_CRYPTO_new()
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

int CRYPTO::AES_setup_key(const BYTES key, SIZE keylen, AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return -1;
    }

    ctx->key or (ctx->key = new BYTE[keylen + 1]);

    if (not ctx->key)
    {
        return -1;
    }

    memcpy(ctx->key, key, keylen);
    ctx->key[keylen] = 0;

    return 0;
}

int CRYPTO::AES_setup_iv(const BYTES iv, SIZE ivlen, AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return -1;
    }

    ctx->iv or (ctx->iv = new BYTE[ivlen + 1]);

    if (not ctx->iv)
    {
        return -1;
    }

    memcpy(ctx->iv, iv, ivlen);
    ctx->iv[ivlen] = 0;

    return 0;
}

int CRYPTO::AES_read_key(const AES_CRYPTO ctx, SIZE keylen, BYTES *key)
{
    if (not ctx or not ctx->key)
    {
        return -1;
    }

    *key or (*key = new BYTE[keylen + 1]);

    if (not *key)
    {
        return -1;
    }

    memcpy(*key, ctx->key, keylen);
    (*key)[keylen] = 0;

    return 0;
}

int CRYPTO::AES_read_iv(const AES_CRYPTO ctx, SIZE ivlen, BYTES *iv)
{
    if (not ctx or not ctx->iv)
    {
        return -1;
    }

    *iv or (*iv = new BYTE[ivlen + 1]);

    if (not *iv)
    {
        return -1;
    }

    memcpy(*iv, ctx->iv, ivlen);
    (*iv)[ivlen] = 0;

    return 0;
}

int CRYPTO::AES_init(const BYTES passphrase, SIZE passlen, const BYTES salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return -1;
    }

    if (passphrase and passlen /*and (not ctx->key or not ctx->key)*/)
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

        op == ENCRYPT and (ctx->encrinit = 1) and ctx->key and ctx->iv and EVP_EncryptInit_ex(ctx->encr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv);
        op == DECRYPT and (ctx->decrinit = 1) and ctx->key and ctx->iv and EVP_DecryptInit_ex(ctx->decr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv);
    }

    return 0;
}

int CRYPTO::AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, AES_CRYPTO ctx)
{
    return AES_init(passphrase, passlen, salt, rounds, ENCRYPT, ctx) == 0 and AES_init(0, 0, 0, 0, DECRYPT, ctx) == 0 ? 0 : -1;
}

int CRYPTO::AES_ctx_dup(AES_CRYPTO dest, const AES_CRYPTO src)
{
    if(not dest or not src)
    {
        return -1;
    }

    dest->decr = src->decr;
    dest->encr = src->encr;

    dest->decrinit = src->decrinit;
    dest->encrinit = src->encrinit;

    return 0;
}

int CRYPTO::AES_encrypt(AES_CRYPTO ctx, const BYTES in, SIZE inlen, BYTES *out)
{
    if (not ctx)
    {
        return -1;
    }

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

    if (not *out)
    {
        return -1;
    }

    memset(*out, 0, c_len + 1);

    if (EVP_EncryptUpdate(ctx->encr, *out, &c_len, in, inlen) <= 0)
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

int CRYPTO::AES_decrypt(AES_CRYPTO ctx, const BYTES in, SIZE inlen, BYTES *out)
{
    if (not ctx)
    {
        return -1;
    }

    int delta = inlen % AES_BLOCK_SIZE;
    (delta < 8 and (inlen -= delta)) or (inlen += AES_BLOCK_SIZE - delta);

    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = inlen, f_len = 0;

    if (EVP_DecryptInit_ex(ctx->decr, EVP_aes_256_cbc(), 0, ctx->key, ctx->iv) <= 0)
    {
        return -1;
    }

    *out or (*out = new BYTE[p_len + 1]);

    if (not *out)
    {
        return -1;
    }

    memset(*out, 0, p_len + 1);

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

void CRYPTO::AES_CRYPTO_free(AES_CRYPTO ctx)
{
    if (not ctx)
    {
        return;
    }

    delete ctx->key;
    delete ctx->iv;

    if (ctx->encr)
    {
        EVP_CIPHER_CTX_free(ctx->encr);
    }

    if (ctx->decr)
    {
        EVP_CIPHER_CTX_free(ctx->decr);
    }
}
