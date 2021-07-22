#include "sha.hh"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <string.h>

using namespace std;

int digest(BYTES in, SIZE inlen, const CHAR *digest_name, BYTES *out)
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

int sha256(BYTES in, SIZE inlen, BYTES *out)
{
    return digest(in, inlen, "sha256", out);
}

int sha256(BYTES in, SIZE inlen, PLAINTEXT *out)
{
    SIZE outlen = 2 * SHA256_DIGEST_LENGTH;
    BYTES hash = 0;

    if (sha256(in, inlen, &hash) < 0)
    {
        return -1;
    }

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    delete hash;

    *out or (*out = new CHAR[outlen + 1]);
    strcpy(*out, ss.str().data());

    return outlen;
}
