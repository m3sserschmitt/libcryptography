/** \file aes.h
 * \brief AES encryption & decryption.
 * 
 * AES_encrypt & AES_decrypt functions allocate required memory dynamically for 'out'
 * parameter. AES_encrypt 'out' will be base64 encoded & AES_decrypt takes base64 encoded
 * data for it's 'in' parameter.
 */

#include "crypto/v3/aes.h"

/**
 * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
 * negative error code.
 * 
 * @param encr: initialized encryption context;
 * @param in: data to be encrypted;
 * @param inlen: length of data to be encrypted;
 * @param out: if successful, contains base64 encoded encrypted data. If out it's
 * null, then required memory will be allocated;
 */
int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BASE64 *out);

/**
 * Perfoms AES decryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param decr: initialized decryption context;
 * @param in: base64 encoded data to be decrypted;
 * @param out: if successful, contains decrypted data. If out it's null, then required 
 * memory will be allocated;
 * @param outlen: decrypted data length;
 */
int AES_decrypt(DECRYPT_CONTEXT decr, BASE64 in, BYTES *out, SIZE &outlen);