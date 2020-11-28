/** \file aes.h
 * \brief AES encryption & decryption.
 * 
 * AES_encrypt & AES_decrypt functions allocate required memory dynamically for 'out'
 * parameter.
 */

#include "crypto/v1/aes.h"

/**
 * Initialize AES encryption context. Return 1 if initialization successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param encr: AES encryption context. If encr parameter it's null, then a new context
 * will be allocated;
 * @param key: AES cipher key;
 * @param keylen: size of key;
 * @param salt: salt to be used in sha256 iterations;
 * @param rounds: number of sha256 iterations;
 */
int AES_encrypt_init(ENCRYPT_CONTEXT *encr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Initialize AES decryption context. Return 1 if initialization successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param decr: AES decryption context. If encr parameter it's null, then a new context
 * will be allocated;
 * @param key: AES cipher key;
 * @param keylen: size of key;
 * @param salt: salt to be used in sha256 iterations;
 * @param rounds: number of sha256 iterations;
 */
int AES_decrypt_init(DECRYPT_CONTEXT *decr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Initialize AES for encryption and decryption. Return 1 if successful,
 * otherwise return an appropriate negative error code.
 * 
 * @param encr: if successful, contains initialized encryption context. If
 * encr points to null, then a new context will be created;
 * @param decr: if successful, contains initialized decryption context. If
 * decr points to null, then a new context will be created;
 * @param key: cipher key for encrytion & decryption;
 * @param keylen: key length in bytes;
 * @param salt: salt to be used in SHA1 iterations (or null if salt not desired);
 * @param rounds: number of SHA1 itarations;
 */
int AES_init(ENCRYPT_CONTEXT *encr, DECRYPT_CONTEXT *decr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Performs AES encryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param encr: initialized encryption context;
 * @param in: data to be encrypted;
 * @param inlen: size of data to be encrypted;
 * @param out: if successful, contains encrypted data. If out it's null, then required
 * memory will be allocated in order to perform encryption;
 * @param outlen: encrypted data length; 
 */
int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);

/**
 * Perfoms AES decryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param decr: initialized decryption context;
 * @param in: data to be decrypted;
 * @param inlen: length of data to be decrypted;
 * @param out: if successful, contains decrypted data. If out it's null, then required
 * memory will be allocated in order to perform decryption;
 * @param outlen: decrypted data length;
 */
int AES_decrypt(DECRYPT_CONTEXT decr, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);