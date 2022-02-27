#include "base64.hh"

#include <openssl/evp.h>
#include <string.h>

int CRYPTO::base64_get_decoded_size(SIZE inlen)
{
  return 3 * inlen / 4;
}

int CRYPTO::base64_get_encoded_size(SIZE inlen)
{
  return ((4 * inlen / 3) + 3) & ~3;
}

int CRYPTO::base64_encode(const BYTE *in, SIZE inlen, BASE64 *out)
{
  *out or (*out = new CHAR[base64_get_encoded_size(inlen) + 1]);

  return *out ? EVP_EncodeBlock((BYTES)(*out), in, inlen) : -1;
}

int CRYPTO::base64_decode(const CHAR *in, BYTES *out)
{
  SIZE inlen = strlen(in);

  *out or (*out = new BYTE[base64_get_decoded_size(inlen) + 1]);

  return *out ? EVP_DecodeBlock(*out, (const BYTE *)in, inlen) : -1;
}
