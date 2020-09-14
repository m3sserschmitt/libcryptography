#include "aes.h"
#include "base64.h"
#include "rsa.h"
#include "sha.h"
#include "errors.h"
#include "cleanup.h"

void init();

void cleanup();

#define cryptography_init() init()
#define cryptography_cleanup() cleanup()