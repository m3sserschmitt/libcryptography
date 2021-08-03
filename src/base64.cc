#include "base64.hh"

#include <openssl/evp.h>
#include <string.h>

int CRYPTO::base64_encode(const BYTES in, SIZE inlen, BASE64 *out)
{
  SIZE outlen = 4 * ((inlen + 2) / 3);
  *out or (*out = new CHAR[outlen + 1]);

  return *out ? EVP_EncodeBlock((BYTES)(*out), in, inlen) : -1;
}

int CRYPTO::base64_decode(const BASE64 in, BYTES *out)
{
  SIZE inlen = strlen(in);

  SIZE outlen = 3 * inlen / 4;
  *out or (*out = new BYTE[outlen + 1]);

  return *out ? EVP_DecodeBlock(*out, (BYTES)in, inlen) : -1;
}
