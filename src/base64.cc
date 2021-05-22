#include "base64.hh"

#include <openssl/evp.h>
#include <string.h>

int base64_encode(BYTES in, SIZE inlen, BASE64 *out)
{
  SIZE outlen = 4 * ((inlen + 2) / 3);
  *out or (*out = (BASE64)calloc(outlen + 1, sizeof(char)));

  return *out ? EVP_EncodeBlock((BYTES)(*out), in, inlen) : -1;
}

int base64_decode(BASE64 in, BYTES *out)
{
  SIZE inlen = strlen(in);

  SIZE outlen = 3 * inlen / 4;
  *out or (*out = (BYTES)calloc(outlen + 1, sizeof(BYTE)));

  return *out ? EVP_DecodeBlock(*out, (BYTES)in, inlen) : -1;
}
