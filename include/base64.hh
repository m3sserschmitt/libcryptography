#ifndef BASE64_HH
#define BASE64_HH

#include "types.hh"

int base64_encode(BYTES in, SIZE inlen, BASE64 *out);

int base64_decode(BASE64 in, BYTES *out);

#endif
