#include "sha.hh"

#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <string.h>

using namespace std;

int sha256(BYTES in, SIZE inlen, BYTES *out)
{
    SHA256_CTX *ctx = new SHA256_CTX;
    *out or (*out = (BYTES)calloc(SHA256_DIGEST_LENGTH, sizeof(BYTE)));

    if (not SHA256_Init(ctx))
    {
        return -1;
    }

    if (not SHA256_Update(ctx, in, inlen))
    {
        return -1;
    }

    int result = SHA256_Final(*out, ctx);

    delete ctx;

    return not result ? -1 : SHA256_DIGEST_LENGTH;
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

    free(hash);
    *out or (*out = (PLAINTEXT)calloc(outlen + 1, sizeof(char)));
    strcpy(*out, ss.str().data());

    return outlen;
}
