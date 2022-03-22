#include "cryptography/aes_types.hh"
#include "cryptography/aes_auth.hh"
#include "cryptography/random.hh"

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <string.h>

int CRYPTO::AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out)
{
    if(not ctx or not ctx->encr or not in)
    {
        return -1;
    }
    
    BYTES iv = new BYTE[AES_GCM_IV_SIZE + 1];
    BYTES tag = new BYTE[AES_GCM_TAG_SIZE + 1];

    int len;
    int f_len;

    int output_size = AES_GCM_TAG_SIZE + AES_GCM_IV_SIZE + inlen;
    BYTES outptr;

    int ret = 0;

    if (not tag or not iv)
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_EncryptInit_ex(ctx->encr, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        ret = -1;
        goto cleanup;
    }

#if AES_GCM_IV_SIZE != AES_GCM_DEFAULT_IV_SIZE

    /*Set IV length if default 12 bytes(96 bits) is not appropriate */

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->encr, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL))
    {
        ret = -1;
        goto cleanup;
    }

#endif

    // new IV generated on every encryption cycle;
    rand_bytes(AES_GCM_IV_SIZE, &iv);

    if (1 != EVP_EncryptInit_ex(ctx->encr, NULL, NULL, ctx->key, iv))
    {
        ret = -1;
        goto cleanup;
    }

    if (aad and aadlen)
    {
        if (1 != EVP_EncryptUpdate(ctx->encr, NULL, &len, aad, aadlen))
        {
            ret = -1;
            goto cleanup;
        }
    }

    // allocate memory for output data if required
    // plaintext size = ciphertext size

    if (not *out and not(*out = new BYTE[output_size + 1]))
    {
        ret = -1;
        goto cleanup;
    }

    outptr = *out;

    if (1 != EVP_EncryptUpdate(ctx->encr, outptr + AES_GCM_IV_SIZE, &len, in, inlen))
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_EncryptFinal_ex(ctx->encr, outptr + len + AES_GCM_IV_SIZE, &f_len))
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->encr, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag))
    {
        ret = -1;
        goto cleanup;
    }

    memcpy(outptr, iv, AES_GCM_IV_SIZE);
    memcpy(outptr + AES_GCM_IV_SIZE + f_len + len, tag, AES_GCM_TAG_SIZE);

cleanup:
    delete[] tag;
    delete[] iv;

    tag = 0;
    iv = 0;

    EVP_CIPHER_CTX_reset(ctx->encr);

    return ret < 0 ? -1 : f_len + len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;
}

int CRYPTO::AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out)
{
    return AES_auth_encrypt(ctx, in, inlen, 0, 0, out);
}

int CRYPTO::AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out)
{
    if(not ctx or not ctx->decr or not in)
    {
        return -1;
    }

    BYTES iv = new BYTE[AES_GCM_IV_SIZE + 1];
    BYTES tag = new BYTE[AES_GCM_TAG_SIZE + 1];

    int len;
    int f_len;

    // size of decrypted data = size of encrypted data
    int decrlen = inlen - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;

    int ret = 0;

    if (not tag or not iv)
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_DecryptInit_ex(ctx->decr, EVP_aes_256_gcm(), NULL, NULL, NULL))
    {
        ret = -1;
        goto cleanup;
    }

#if AES_GCM_IV_SIZE != AES_GCM_DEFAULT_IV_SIZE
    if (1 != EVP_CIPHER_CTX_ctrl(ctx->decr, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL))
    {
        ret = -1;
        goto cleanup;
    }
#endif

    memcpy(iv, in, AES_GCM_IV_SIZE);

    if (1 != EVP_DecryptInit_ex(ctx->decr, NULL, NULL, ctx->key, iv))
    {
        ret = -1;
        goto cleanup;
    }

    if (aad and aadlen)
    {
        if (1 != EVP_DecryptUpdate(ctx->decr, NULL, &len, aad, aadlen))
        {
            ret = -1;
            goto cleanup;
        }
    }

    if (not *out and not(*out = new BYTE[decrlen + 1]))
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_DecryptUpdate(ctx->decr, *out, &len, in + AES_GCM_IV_SIZE, decrlen))
    {
        ret = -1;
        goto cleanup;
    }

    memcpy(tag, in + inlen - AES_GCM_TAG_SIZE, AES_GCM_TAG_SIZE);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx->decr, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag))
    {
        ret = -1;
        goto cleanup;
    }

    if (1 != EVP_DecryptFinal_ex(ctx->decr, *out + len, &f_len))
    {
        ret = -1;
        goto cleanup;
    }

cleanup:

    delete[] tag;
    delete[] iv;

    tag = 0;
    iv = 0;

    EVP_CIPHER_CTX_reset(ctx->decr);

    return ret < 0 ? -1 : len + f_len;
}

int CRYPTO::AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out)
{
    return AES_auth_decrypt(ctx, in, inlen, 0, 0, out);
}
