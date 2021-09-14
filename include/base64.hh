/**
 * @file base64.hh
 * @author Romulus-Emanuel Ruja
 * @brief This file contain functions for base64 encoding & decoding.
 * @version 0.1
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */

#ifndef BASE64_HH
#define BASE64_HH

#include "types.hh"

namespace CRYPTO
{
    /**
 * @brief Perform base64 encoding.
 * 
 * @param in Data to be encoded.
 * @param inlen Length of data in bytes.
 * @param out Encoded data (if null, then it is dynamically allocated).
 * @return int Size of encoded data.
 */
    int base64_encode(const BYTE *in, SIZE inlen, BASE64 *out);

    /**
 * @brief Perform base64 decoding.
 * 
 * @param in Data to be decoded.
 * @param out Decoded data (if null, then it is dynamically allocated).
 * @return int Size of decoded data.
 */
    int base64_decode(const CHAR *in, BYTES *out);
}

#endif
