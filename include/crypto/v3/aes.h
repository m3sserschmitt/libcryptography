/** \file aes.h
 * \brief AES encryption & decryption.
 * 
 * AES_encrypt output it'll be base64 encoded and AES_decrypt takes base64 encoded data.
 */

#include "crypto/v2/aes.h"

/**
 * Get base64 encoded size of AES encrypted data.
 * 
 * @param inlen: size of data to be encrypted, then base64 encoded.
 */
size_t AES_get_encoded_size(SIZE inlen);

/**
 * Get plaintext size of base64 encoded AES encrypeted data.
 * 
 * @param inlen: size of deta to be base64 decoded, then AES decrypted.
 */
size_t AES_get_decoded_size(SIZE inlen);

/**
 * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
 * negative error code.
 * 
 * @param encr: initialized encryption context;
 * @param in: data to be encrypted;
 * @param inlen: length of data to be encrypted;
 * @param out: if successful, contains base64 encoded encrypted data;
 */
int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BASE64 out);

/**
 * Perfoms AES decryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param decr: initialized decryption context;
 * @param in: base64 encoded data to be decrypted;
 * @param out: if successful, contains decrypted data;
 * @param outlen: decrypted data length;
 */
int AES_decrypt(DECRYPT_CONTEXT decr, BASE64 in, BYTES out, SIZE &outlen);
