#ifndef RANDOM_HH
#define RANDOM_HH

#include "types.hh"

namespace CRYPTO
{
    int rand_seed(SIZE len);

    int rand_bytes(SIZE len, BYTES *out);
}

#endif
