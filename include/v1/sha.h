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

/*
     * Creates SHA256 hexdigest of provided data.
     * 
     * in: data to compute SHA256; 
     * inlen: data length;
     */
std::string sha256(BYTES in, SIZE inlen);

/*
     * Creates SHA256 hexdigest of input data.
     * 
     * in: data to compute SHA256; 
     */
std::string sha256(std::string in);

#ifndef SHA_H_1
#define SHA_H_1

#define sha256_calculate(in, inlen) compute_SHA256(in, inlen)
#define sha256_message_digest(in) compute_SHA256(in)

#endif