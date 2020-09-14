#include "../../include/v1/cryptography.h"

#include <openssl/err.h>

void init()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup()
{
    EVP_cleanup();
	ERR_free_strings();
}