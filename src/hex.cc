#include "cryptography/hex.hh"

#include <sstream>
#include <iomanip>
#include <string.h>

using namespace std;

int CRYPTO::hex(const BYTE *in, SIZE inlen, PLAINTEXT *out)
{
    stringstream ss;
    SIZE i = 0;

    for (; i < inlen; i++)
    {
        ss << std::hex << setw(2) << setfill('0') << (int)in[i];
    }

    i *= 2;

    *out or (*out = new CHAR[i + 1]);

    if (not *out)
    {
        return -1;
    }

    strcpy(*out, ss.str().c_str());

    return i;
}

int CRYPTO::fromHex(const CHAR *in, BYTES *out)
{
    SIZE inlen = strlen(in);

    if (inlen % 2)
    {
        return -1;
    }

    int outlen = inlen / 2;

    if (not *out and not(*out = new BYTE[outlen + 1]))
    {
        return -1;
    }

    string input = in;

    for (int i = 0; i < inlen; i += 2)
    {

        (*out)[i / 2] = std::stoul(input.substr(i, 2), nullptr, 16);
    }

    return outlen;
}
