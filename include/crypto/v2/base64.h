#include "crypto/v1/base64.h"

void base64_encode(BYTES in, SIZE inlen, BASE64 *out);

void base64_decode(BASE64 in, BYTES *out, SIZE &outlen);
