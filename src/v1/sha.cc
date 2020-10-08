#include "../../include/v1/sha.h"

#include <sstream>
#include <iomanip>
#include <string.h>

DIGEST compute_SHA256(BYTES in, SIZE inlen)
{
    unsigned char *output_buffer = (unsigned char *)malloc(32);
    memset(output_buffer, 0, 32);

    SHA256(in, inlen, output_buffer);

    DIGEST digest = (DIGEST)malloc(32);

    for (int i = 0; i < 32; i++)
    {
        digest[i] = (int)output_buffer[i];
    }

    free(output_buffer);

    return digest;
}

DIGEST compute_SHA256(PLAINTEXT in)
{
    return compute_SHA256((unsigned char *)in, strlen(in));
}

std::string sha256(DIGEST digest)
{
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');

    for (int i = 0; i < 32; i++)
    {
        shastr << std::setw(2) << digest[i];
    }

    return shastr.str();
}

std::string sha256(std::string in)
{
    return sha256(compute_SHA256((char *)in.data()));
}

std::string sha256(BYTES in, SIZE inlen)
{
    return sha256(compute_SHA256(in, inlen));
}