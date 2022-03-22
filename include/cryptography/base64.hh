/**
 * @file base64.hh
 * @author Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>
 * @brief This file contain functions for base64 encoding & decoding.
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
    * @brief Get size of base64 encoded data
    * 
    * @param inlen Size of data to be encoded
    * @return int Size of base64 encoded data
    */
   SIZE base64_get_encoded_size(SIZE inlen);

   /**
    * @brief Get size of base64 decoded data
    * 
    * @param in Base64 encoded data
    * @return int Size of base64 decoded data
    */
   SIZE base64_get_decoded_size(const CHAR *in);

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
