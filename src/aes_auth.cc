#include "../include/aes.hh"
#include "../include/random.hh"

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
    bool iv_autoset;
    bool iv_append;

    _AES_CRYPTO *ref;
};

int CRYPTO::AES_init_ctx(CRYPTO_OP op, AES_CRYPTO ctx)
{
    if ((op == ENCRYPT and not ctx->encrinit) or
        (op == DECRYPT and not ctx->decrinit))
    {
        EVP_CIPHER_CTX **aes = 0;

        op == ENCRYPT and (aes = &ctx->encr);
        op == DECRYPT and (aes = &ctx->decr);

        if (not(*aes or (*aes = EVP_CIPHER_CTX_new())))
        {
            return -1;
        }

        if (EVP_CIPHER_CTX_init(*aes) <= 0)
        {
            return -1;
        }

        op == ENCRYPT and (ctx->encrinit = 1);
        op == DECRYPT and (ctx->decrinit = 1);
    }

    return 0;
}

int CRYPTO::AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out)
{
    if (1 != EVP_EncryptInit_ex(ctx->encr, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        return -1;
    }

#if AES_GCM_IV_SIZE != AES_GCM_DEFAULT_IV_SIZE

    /*Set IV length if default 12 bytes(96 bits) is not appropriate */

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->encr, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL))
    {
        return -1;
    }

#endif

    // new IV generated on every encryption cycle;

    if (not ctx->iv and not(ctx->iv = new BYTE[AES_GCM_IV_SIZE + 1]))
    {
        return -1;
    }

    rand_bytes(AES_GCM_IV_SIZE, &ctx->iv);

    if (1 != EVP_EncryptInit_ex(ctx->encr, NULL, NULL, ctx->key, ctx->iv))
    {
        return -1;
    }

    int len;

    if (aad and aadlen)
    {
        if (1 != EVP_EncryptUpdate(ctx->encr, NULL, &len, aad, aadlen))
        {
            return -1;
        }
    }

    // allocate memory for output data if required
    // in GCM, plaintext size = ciphertext size

    int output_size = AES_GCM_TAG_SIZE + AES_GCM_IV_SIZE + inlen;

    if (not *out and not(*out = new BYTE[output_size + 1]))
    {
        return -1;
    }

    BYTES outptr = *out;

    if (1 != EVP_EncryptUpdate(ctx->encr, outptr + AES_GCM_IV_SIZE, &len, in, inlen))
    {
        return -1;
    }

    int f_len;

    if (1 != EVP_EncryptFinal_ex(ctx->encr, outptr + len + AES_GCM_IV_SIZE, &f_len))
    {
        return -1;
    }

    BYTES tag = new BYTE[AES_GCM_TAG_SIZE + 1];

    if (not tag)
    {
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->encr, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag))
    {
        return -1;
    }

    memcpy(outptr, ctx->iv, AES_GCM_IV_SIZE);
    memcpy(outptr + AES_GCM_IV_SIZE + f_len + len, tag, AES_GCM_TAG_SIZE);

    delete[] tag;
    tag = 0;

    return f_len + len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;
}

int CRYPTO::AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out)
{
    if (1 != EVP_DecryptInit_ex(ctx->decr, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        return -1;
    }

#if AES_GCM_IV_SIZE != AES_GCM_DEFAULT_IV_SIZE
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->decr, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL))
    {
        return -1;
    }
#endif

    if (not ctx->iv and not(ctx->iv = new BYTE[AES_GCM_IV_SIZE + 1]))
    {
        return -1;
    }

    memcpy(ctx->iv, in, AES_GCM_IV_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx->decr, NULL, NULL, ctx->key, ctx->iv))
    {
        return -1;
    }

    int len;

    if (1 != EVP_DecryptUpdate(ctx->decr, NULL, &len, aad, aadlen))
    {
        return -1;
    }

    // size of decrypted data = size of encrypted data
    int decrlen = inlen - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;

    if (not *out and not(*out = new BYTE[decrlen + 1]))
    {
        return -1;
    }

    if(1 != EVP_DecryptUpdate(ctx->decr, *out, &len, in + AES_GCM_IV_SIZE, decrlen))
    {
        return -1;
    }

    BYTES tag = new BYTE[AES_GCM_TAG_SIZE + 1];

    if(not tag)
    {
        return -1;
    }

    memcpy(tag, in + inlen - AES_GCM_TAG_SIZE, AES_GCM_TAG_SIZE);

    if(1 != EVP_CIPHER_CTX_ctrl(ctx->decr, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag))
    {
        return -1;
    }

    int f_len;

    if(1 != EVP_DecryptFinal_ex(ctx->decr, *out + len, &f_len))
    {
        return -1;
    }

    return len + f_len;
}
