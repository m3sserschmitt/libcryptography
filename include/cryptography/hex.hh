#include "types.hh"

namespace CRYPTO
{
    /**
     * @brief Convert hashed data into hexadecimal notation.
     *
     * @param in Hashed data to be converted.
     * @param inlen Size of input data in bytes.
     * @param out Hex string.
     * @return int Size of output string, or -1 if failure.
     */

    int hex(const BYTE *in, SIZE inlen, PLAINTEXT *out);

    int fromHex(const CHAR *in, BYTES *out);
}
