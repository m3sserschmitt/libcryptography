#include "../v2/aes.h"

/*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encr: initialized encryption context;
     * in: data to be encrypted;
     * inlen: length of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     */
int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BASE64 *out);

/* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decrypt_ctx: initialized decryption context;
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */
int AES_decrypt(DECRYPT_CTX decr, BASE64 in, BYTES *out, SIZE &outlen);