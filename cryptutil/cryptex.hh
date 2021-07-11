#include "util/cmd.hh"

#include <cryptography/cryptography.hh>

typedef struct 
{
    AES_CRYPTO aes;
    RSA_CRYPTO rsa;
} _CRYPTO;

typedef _CRYPTO *CRYPTO;

bool read_stdin(BYTES *in, SIZE &inlen, CRYPTO crypto);
bool read_password(PLAINTEXT *argv, SIZE argc, CRYPTO crypto);

BYTES read_file(PLAINTEXT *argv, SIZE argc, SIZE &file_size);
bool write_file(BYTES data, SIZE datalen, PLAINTEXT *argv, SIZE argc);

int cryptography(CRYPTO ctx, BYTES in, SIZE inlen, PLAINTEXT *argv, SIZE argc, BYTES *out);
