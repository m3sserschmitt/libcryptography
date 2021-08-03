/**
 * @file sha.hh
 * @author Romulus-Emanuel Ruja
 * @brief This file contains functions for SHA hashing.
 * @version 0.1
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */

#ifndef SHA_HH
#define SHA_HH

#include "types.hh"

namespace CRYPTO
{
    /**
 * @brief Perform data hashing using specified algorithm with digest_name parameter.
 * 
 * @param in Data to be hashed.
 * @param inlen Data size if bytes.
 * @param digest_name Digest name ("sha256", "sha512" etc).
 * @param out Hashed data
 * @return int Size of hashed data if success, -1 if failure.
 */
    int digest(const BYTES in, SIZE inlen, const CHAR *digest_name, BYTES *out);

/**
 * @brief Convert hashed data into hexadecimal notation.
 * 
 * @param in Hashed data to be converted.
 * @param inlen Size of input data in bytes.
 * @param out Hex string.
 * @return int Size of output string, or -1 if failure.
 */

    int hex(const BYTES in, SIZE inlen, PLAINTEXT *out);

    /**
 * @brief Perform SHA256 hashing.
 * 
 * @param in Data to be hashed.
 * @param inlen Size of data in bytes.
 * @param out Hashed data (if null, then it is dynamically allocated).
 * @return int Size of hash if success, otherwise -1.
 */
    int sha256(const BYTES in, SIZE inlen, BYTES *out);

    /**
 * @brief Perform SHA256 hashing.
 * 
 * @param in Data to be hashed.
 * @param inlen Size of data in bytes.
 * @param out Hashed data in hex format (if null, then it is dynamically allocated).
 * @return int Size of hash if success, otherwise -1.
 */
    int sha256(const BYTES in, SIZE inlen, PLAINTEXT *out);
}

#endif
