#include "crypto/v1/init.h"

#include <openssl/err.h>
#include <openssl/evp.h>

void cryptography_init()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
} 

void cryptography_cleanup()
{
    EVP_cleanup();
	ERR_free_strings();
}