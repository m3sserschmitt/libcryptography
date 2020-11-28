#include "crypto/v1/sha.h"
#include "crypto/v1/mem.h"

#include <openssl/sha.h>

#include <sstream>
#include <iomanip>
#include <string.h>

using namespace std;

DIGEST SHA256_digest(BYTES in, SIZE inlen)
{
    unsigned char *out;
    allocate_memory(&out, 64);

    SHA256(in, inlen, out);

    DIGEST digest;
    allocate_memory(&digest, 32);
    
    for (int i = 0; i < 32; i++)
    {
        digest[i] = (int)out[i];
        
    }

    free_memory(out);

    return digest;
}

DIGEST SHA256_digest(PLAINTEXT in)
{
    return SHA256_digest((BYTES)in, strlen(in));
}

string SHA256_hexdigest(DIGEST digest)
{
    stringstream shastr;
    shastr << hex << setfill('0');

    for (int i = 0; i < 32; i++)
    {
        shastr << std::setw(2) << digest[i];
    }
    
    return shastr.str();;
}

string SHA256_hexdigest(PLAINTEXT in)
{
    return SHA256_hexdigest(SHA256_digest(in));
}

string SHA256_hexdigest(BYTES in, SIZE inlen)
{
    return SHA256_hexdigest(SHA256_digest(in, inlen));
}
