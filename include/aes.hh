/**
 * @file aes.hh
 * @author Romulus-Emanuel Ruja
 * @brief This file contains functions for basic AES operations.
 * @version 0.1
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */


#ifndef AES_HH
#define AES_HH

#include "types.hh"


/**
 * @brief Create new AES encryption / decryption context.
 * 
 * @return AES_CRYPTO AES encryption / decryption context.
 */
AES_CRYPTO AES_CRYPTO_new();


/**
 * @brief Initialize AES contex for specified operation.
 * 
 * @param passphrase Passphrase to be used for encryption.
 * @param passlen Length of passphrase in bytes.
 * @param salt Salt to be used (or null in not desired).
 * @param rounds Number of encryption rounds.
 * @param op Cryptographic operation: ENCRYPT / DECRYPT.
 * @param ctx AES context to be initialized.
 * @return int 0 for success, -1 for failure.
 */
int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx);


/**
 * @brief Initialize AES context for both encryption and decryption.
 * 
 * @param passphrase Passphrase to be used for encryption.
 * @param passlen Length of passphrase in bytes.
 * @param salt Salt to be used (or null in not desired).
 * @param rounds Number of encryption rounds.
 * @param ctx AES context to be initialized.
 * @return int 0 for success, -1 for failure.
 */
int AES_init(BYTES passphrase, SIZE passlen, BYTES salt, int rounds, AES_CRYPTO ctx);


/**
 * @brief Perform AES encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @return int Size of encrypted data if success, -1 if failure.
 */
int AES_encrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);


/**
 * @brief Perform AES decryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be decrypted.
 * @param inlen Data length in bytes.
 * @param out Decrypted data (if null, then it is dynamically allocated).
 * @return int Size of decrypted data if success, -1 if failure.
 */
int AES_decrypt(AES_CRYPTO ctx, BYTES in, SIZE inlen, BYTES *out);

#endif
