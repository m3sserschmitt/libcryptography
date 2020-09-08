

/*
 * Openssl initialization & cleanup.
*/

#include "../include/cryptography.h"

#include <openssl/err.h>

void Cryptography::init()
{
	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();
}

void Cryptography::cleanup()
{
	EVP_cleanup();
	ERR_free_strings();
}