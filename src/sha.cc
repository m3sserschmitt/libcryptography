#include "cryptography/sha.hh"
#include "cryptography/hex.hh"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>

using namespace std;

int CRYPTO::digest(const BYTE *in, SIZE inlen, const CHAR *digest_name, BYTES *out)
{
    const EVP_MD *md = EVP_get_digestbyname(digest_name);
    
    if (not md)
    {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (not ctx)
    {
        EVP_MD_CTX_free(ctx);

        return -1;
    }

    if (not EVP_DigestInit_ex(ctx, md, 0))
    {
        EVP_MD_CTX_free(ctx);

        return -1;
    }

    if (not EVP_DigestUpdate(ctx, in, inlen))
    {
        EVP_MD_CTX_free(ctx);

        return -1;
    }

    *out or (*out = new BYTE[EVP_MAX_MD_SIZE + 1]);

    unsigned int outlen;
    if (not *out or not EVP_DigestFinal_ex(ctx, *out, &outlen))
    {
        EVP_MD_CTX_free(ctx);

        return -1;
    }

    EVP_MD_CTX_free(ctx);

    return outlen;
}

int CRYPTO::sha256(const BYTE *in, SIZE inlen, BYTES *out)
{
    return digest(in, inlen, "sha256", out);
}

int CRYPTO::sha256(const BYTE *in, SIZE inlen, PLAINTEXT *out)
{
    BYTES hash = 0;

    if (sha256(in, inlen, &hash) < 0)
    {
        return -1;
    }

    int result = hex(hash, SHA256_DIGEST_LENGTH, out);

    delete hash;

    return result;
}
