#include "random.hh"

#include <openssl/rand.h>

int rand_seed(SIZE bytes)
{
    return RAND_load_file("/dev/random", bytes) == (int)bytes ? 0 : -1;
}

int rand_bytes(BYTES randbytes, SIZE len)
{
    return RAND_bytes(randbytes, len) ? 0 : -1;
}