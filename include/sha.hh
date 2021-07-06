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


#include "types.hh"


/**
 * @brief Perform SHA256 hashing.
 * 
 * @param in Data to be hashed.
 * @param inlen Size of data in bytes.
 * @param out Hashed data (if null, then it is dynamically allocated).
 * @return int Size of hash if success, otherwise -1.
 */
int sha256(BYTES in, SIZE inlen, BYTES *out);


/**
 * @brief Perform SHA256 hashing.
 * 
 * @param in Data to be hashed.
 * @param inlen Size of data in bytes.
 * @param out Hashed data in hex format (if null, then it is dynamically allocated).
 * @return int Size of hash if success, otherwise -1.
 */
int sha256(BYTES in, SIZE inlen, PLAINTEXT *out);
