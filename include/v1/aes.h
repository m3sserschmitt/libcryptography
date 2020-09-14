#include <openssl/evp.h>
#include <openssl/aes.h>

#include "typedefs.h"

/*
     * Returns size of AES encrypted data.
     * 
     * inlen: size of data to be encrypted;
     */
size_t get_AES_encrypted_size(SIZE inlen);

/*
     * Returns size of AES decrypted data.
     * 
     * inlen: size of encrypted data;
     */
size_t get_AES_decrypted_size(SIZE inlen);

/*
     * Initialize AES encryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * encr: AES encryption context (returned by EVP_CIPHER_CTX_new method);
     * key_data: AES cipher key;
     * keylen: size of key;
     * salt: salt to be used in sha256 iterations;
     * rounds: number of sha256 iterations;
     */
int AES_encrypt_init(ENCRYPT_CTX encr, BYTES key_data, SIZE keylen, BYTES salt, int rounds);

/*
     * Initialize AES decryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * decr: AES decryption context (returned by EVP_CIPHER_CTX_new method);
     * key_data: AES cipher key;
     * keylen: size of key;
     * salt: salt to be used in sha256 iterations;
     * rounds: number of sha256 iterations;
     */
int AES_decrypt_init(DECRYPT_CTX decr, BYTES key_data, SIZE keylen, BYTES salt, int rounds);

/*
     * Initialize AES for encryption and decryption. Returns 1 if successful,
     * otherwise returns an appropriate negative error code.
     * 
     * key: cipher key for encrytion & decryption;
     * keylen: key length in bytes;
     * salt: salt to be used in SHA1 iterations (or null if salt not desired);
     * rounds: number of SHA1 itarations;
     * encr: if successful, contains encryption cipher context object;
     * decr: if successful, contains decryption cipher context object;
     */
int AES_init(BYTES key, SIZE keylen, BYTES salt, int rounds, ENCRYPT_CTX encr, DECRYPT_CTX decr);

/*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encr: initialized encryption context;
     * in: data to be encrypted;
     * inlen: size of data to be encrypted;
     * out: if successful, contains encrypted data;
     * outlen: encrypted data length; 
     */
int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);

/* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decr: initialized decryption context;
     * in: data to be decrypted;
     * inlen: length of data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */
int AES_decrypt(DECRYPT_CTX decr, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);