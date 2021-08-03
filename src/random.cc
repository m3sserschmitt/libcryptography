#include "random.hh"

#include <openssl/rand.h>
#include <string.h>

int CRYPTO::rand_seed(SIZE bytes)
{
    return RAND_load_file("/dev/random", bytes) == (int)bytes ? 0 : -1;
}

int CRYPTO::rand_bytes(SIZE len, BYTES *out)
{
    *out or (*out = new BYTE[len + 1]);

    if(not *out)
    {
        return -1;
    }

    memset(*out, 0, len + 1);

    return RAND_bytes(*out, len) ? 0 : -1;
}