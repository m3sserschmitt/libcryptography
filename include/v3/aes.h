#include "../v2/aes.h"

/*
     * Get base64 encoded size of AES encrypted data.
     * 
     * inlen: size of data to be encrypted, then base64 encoded.
    */
size_t get_AES_encoded_size(SIZE inlen);

/*
     * Get plaintext size of base64 encoded AES encrypeted data.
     * 
     * inlen: size of deta to be base64 decoded, then AES decrypted.
    */
size_t get_AES_decoded_size(SIZE inlen);

/*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encr: initialized encryption context;
     * in: data to be encrypted;
     * inlen: length of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     */
int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BASE64 out);

/* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decr: initialized decryption context;
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */
int AES_decrypt(DECRYPT_CTX decr, BASE64 in, BYTES out, SIZE &outlen);

#ifndef AES_H_3
#define AES_H_3

#define AES_get_encoded_size(inlen) get_AES_encoded_size(inlen)
#define AES_get_decoded_size(inlen) get_AES_decoded_size(inlne)

#endif