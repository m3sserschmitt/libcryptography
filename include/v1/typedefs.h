#include <cstddef>
#include <openssl/evp.h>

typedef unsigned char BYTE;
typedef BYTE* BYTES;

typedef char* PLAINTEXT;
typedef PLAINTEXT BASE64;

typedef int* DIGEST;

typedef size_t SIZE;

typedef EVP_PKEY* KEY;
typedef KEY PUBLIC_KEY;
typedef KEY PRIVATE_KEY;

typedef EVP_CIPHER_CTX* CONTEXT;
typedef CONTEXT DECRYPT_CTX;
typedef CONTEXT ENCRYPT_CTX;
