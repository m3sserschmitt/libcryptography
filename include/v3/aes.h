#include "../v2/aes.h"

/*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encrypt_ctx: initialized encryption context;
     * in: data to be encrypted;
     * inlen: length of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     */
int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, char **out);

/* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decrypt_ctx: initialized decryption context;
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */
int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char **out, size_t &outlen);