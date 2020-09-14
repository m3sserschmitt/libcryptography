#include "typedefs.h"

/*
     * Calculate required memory for base64 decoding.
     * 
     * inlen: size of encoded data;
    */

size_t get_decoded_length(SIZE inlen);

/*
     * Calculate required memory buffer for base64 decoding.
     * 
     * in: base64 encoded data;
     */

size_t get_decoded_length(BASE64 in);

/*
     * Calculate required memory buffer for base64 encoding.
     * 
     * inlen: size of data to be encoded;
     */

size_t get_encoded_length(SIZE inlen);

/*
     * Decode base64 encoded data.
     * 
     * in: base64 data to be decoded;
     * out: decoded data;
     * outlen: decoded data length;
     */
void base64_decode(BASE64 in, BYTES out, SIZE &outlen);

/*
     * Base64 encode.
     * 
     * in: data to be encoded;
     * inlen: size of data to be encoded;
     * out: base64 encoded data;
     */
void base64_encode(BYTES in, SIZE inlen, BASE64 out);