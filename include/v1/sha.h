#include <openssl/sha.h>
#include <string>

/*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * in: data to compute SHA256;
     * inlen: length of input data;
     */
int *compute_SHA256(unsigned char *in, size_t inlen);

/*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * in: data to compute SHA256;
     */
int *compute_SHA256(char *in);

/*
     * Creates a 64 bytes SHA256 hexdigest from a digest.
     * 
     * digest: digest to convert into hexdigest; 
     */
std::string sha256(int *digest);

