/** \file aes.h
 * \brief AES encryption & decryption.
 */ 

#include "typedefs.h"

/**
 * Return size of AES encrypted data.
 * 
 * @param inlen: size of data to be encrypted;
 */
SIZE AES_get_encrypted_size(SIZE inlen);

/**
 * Return size of AES decrypted data.
 * 
 * @param inlen: size of encrypted data;
 */
SIZE AES_get_decrypted_size(SIZE inlen);

/**
 * Initialize AES encryption context. Return 1 if initialization successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param encr: AES encryption context (returned by EVP_CIPHER_CTX_new method);
 * @param key: AES cipher key;
 * @param keylen: size of key;
 * @param salt: salt to be used in sha256 iterations;
 * @param rounds: number of sha256 iterations;
 */
int AES_encrypt_init(ENCRYPT_CONTEXT encr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Initialize AES decryption context. Return 1 if initialization successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param decr: AES decryption context (returned by EVP_CIPHER_CTX_new method);
 * @param key: AES cipher key;
 * @param keylen: size of key;
 * @param salt: salt to be used in sha256 iterations;
 * @param rounds: number of sha256 iterations;
 */
int AES_decrypt_init(DECRYPT_CONTEXT decr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Initialize AES for encryption and decryption. Return 1 if successful,
 * otherwise return an appropriate negative error code. You have to allocate
 * encr & decr contexts using EVP_CIPHER_CTX_new function in order to initialization
 * to be successful.
 * 
 * @param encr: if successful, contains initialized encryption context;
 * @param decr: if successful, contains initialized decryption context;
 * @param key: cipher key for encrytion & decryption;
 * @param keylen: key length in bytes;
 * @param salt: salt to be used in SHA1 iterations (or null if salt not desired);
 * @param rounds: number of SHA1 itarations;
 */
int AES_init(ENCRYPT_CONTEXT encr, DECRYPT_CONTEXT decr, BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Creates AES encryption context. Return newly created context.
 * 
 * @param key: key to be used for encryption;
 * @param keylen: length of key;
 * @param salt: salt to be used into sha256 iterations (or NULL, if not desired);
 * @param rounds: number of sha256 rounds;
 */
ENCRYPT_CONTEXT AES_create_encrypt_ctx(BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Creates AES decryption context. Return newly created context.
 * 
 * @param key: key to be used for decryption;
 * @param keylen: length of key;
 * @param salt: salt to be used into sha256 iterations (or NULL, if not desired);
 * @param rounds: number of sha256 rounds;
 */
DECRYPT_CONTEXT AES_create_decrypt_ctx(BYTES key, SIZE keylen, BYTES salt, int rounds);

/**
 * Free encryption / decryption context;
 * 
 * @param ctx: context to be freed;
 */
void AES_free_context(CIPHER_CONTEXT ctx);

/**
 * Performs AES encryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param encr: initialized encryption context;
 * @param in: data to be encrypted;
 * @param inlen: size of data to be encrypted;
 * @param out: if successful, contains encrypted data;
 * @param outlen: encrypted data length; 
 */
int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);

/**
 * Perfoms AES decryption. Return 1 if successful, otherwise return an appropriate
 * negative error code.
 * 
 * @param decr: initialized decryption context;
 * @param in: data to be decrypted;
 * @param inlen: length of data to be decrypted;
 * @param out: if successful, contains decrypted data;
 * @param outlen: decrypted data length;
 */
int AES_decrypt(DECRYPT_CONTEXT decr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);
