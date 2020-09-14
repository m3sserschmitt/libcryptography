#include "../../include/v2/base64.h"

#include <stdlib.h>
#include <string.h>

void base64_encode(BYTES in, SIZE inlen, BASE64 *out)
{
    size_t required_memory = get_encoded_length(inlen) + 1;
    *out = (char *) malloc(required_memory);
    memset(*out, 0, required_memory);

    base64_encode(in, inlen, *out);
}

void base64_decode(BASE64 in, BYTES *out, SIZE &outlen)
{
    size_t required_memory = get_decoded_length(in) + 1;
    *out = (unsigned char *) malloc(required_memory);
    memset(*out, 0, required_memory);

    base64_decode(in, *out, outlen);
}
