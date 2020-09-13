#include "../v1/base64.h"

void base64_encode(unsigned char *in, size_t inlen, char **out);

void base64_decode(char *in, unsigned char **out, size_t outlen);
