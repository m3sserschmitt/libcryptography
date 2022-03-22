#include "cryptography/base64.hh"

#include <openssl/evp.h>
#include <string.h>

SIZE CRYPTO::base64_get_decoded_size(const CHAR *in)
{
  if (not in)
  {
    return 0;
  }

  SIZE inlen = strlen(in);
  SIZE declen = 3 * inlen / 4;

  in[inlen - 1] == '=' and (declen--);
  in[inlen - 2] == '=' and (declen--);

  return declen;
}

SIZE CRYPTO::base64_get_encoded_size(SIZE inlen)
{
  return ((4 * inlen / 3) + 3) & ~3;
}

int CRYPTO::base64_encode(const BYTE *in, SIZE inlen, BASE64 *out)
{
  SIZE enclen = base64_get_encoded_size(inlen);

  if (not *out and not(*out = new CHAR[enclen + 1]))
  {
    return -1;
  }

  EVP_EncodeBlock((BYTES)(*out), in, inlen);

  return enclen;
}

int CRYPTO::base64_decode(const CHAR *in, BYTES *out)
{
  if(not in)
  {
    return 0;
  }

  SIZE declen = base64_get_decoded_size(in);

  if(not *out and not(*out = new BYTE[declen + 1]))
  {
    return -1;
  }

  EVP_DecodeBlock(*out, (const BYTE *)in, strlen(in));

  return declen;
}
