#include "../v1/sha.h"

/*
     * Creates SHA256 hexdigest of provided data.
     * 
     * in: data to compute SHA256; 
     * inlen: data length;
     */
std::string sha256(unsigned char *in, size_t inlen);

/*
     * Creates SHA256 hexdigest of input data.
     * 
     * in: data to compute SHA256; 
     */
std::string sha256(std::string in);