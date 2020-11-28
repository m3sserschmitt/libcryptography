/**
 * \file base64.h
 * \brief base64 encoding & decoding.
*/

#include "typedefs.h"

/**
 * Calculate required memory for base64 decoding.
 * 
 * @param inlen: size of encoded data;
 */
SIZE base64_get_decoded_length(SIZE inlen);

/**
 * Calculate required memory buffer for base64 decoding.
 * 
 * @param in: base64 encoded data;
 */
SIZE base64_get_decoded_length(BASE64 in);

/**
 * Calculate required memory buffer for base64 encoding.
 * 
 * @param inlen: size of data to be encoded;
 */
SIZE base64_get_encoded_length(SIZE inlen);

/**
 * Decode base64 encoded data.
 * 
 * @param in: base64 data to be decoded;
 * @param out: decoded data;
 * @param outlen: decoded data length;
 */
void base64_decode(BASE64 in, BYTES out, SIZE &outlen);

/**
 * Base64 encode.
 * 
 * @param in: data to be encoded;
 * @param inlen: size of data to be encoded;
 * @param out: base64 encoded data;
 */
void base64_encode(BYTES in, SIZE inlen, BASE64 out);
