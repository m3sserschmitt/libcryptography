#include <openssl/sha.h>
#include <string>

#include "typedefs.h"

/*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * in: data to compute SHA256;
     * inlen: length of input data;
     */
DIGEST compute_SHA256(BYTES in, SIZE inlen);

/*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * in: data to compute SHA256;
     */
DIGEST compute_SHA256(PLAINTEXT in);

/*
     * Creates a 64 bytes SHA256 hexdigest from a digest.
     * 
     * digest: digest to convert into hexdigest; 
     */
std::string sha256(DIGEST digest);

