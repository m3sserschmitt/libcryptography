#include "random.hh"

#include <random>
#include <string.h>

using namespace std;

/*
int CRYPTO::rand_seed(SIZE bytes)
{
    return RAND_load_file("/dev/random", bytes) == (int)bytes ? 0 : -1;
}
*/

int CRYPTO::rand_bytes(SIZE len, BYTES *out)
{
    *out or (*out = new BYTE[len + 1]);

    if (not *out)
    {
        return -1;
    }
    /*
    if(not *out)
    {
        return -1;
    }

    memset(*out, 0, len + 1);

    return RAND_bytes(*out, len) ? 0 : -1;
    */

    random_device dev;
    mt19937 rng(dev());

    uniform_int_distribution<int> dist(0, 255);

    for (SIZE i = 0; i < len; i++)
    {
        (*out)[i] = dist(rng);
    }

    return 0;
}