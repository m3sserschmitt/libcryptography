#include "crypto/v1/rsa.h"

int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *signature, SIZE &signlen);

/*
     * Creates RSA signature. Returns 1 if signing process successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * key: EVP_PKEY object of private key (created by create_private_RSA method);
     * in: data to be signed;
     * inlen: data length;
     * signature: will contain signature, if successful;
     * signlen: will contain signature length in bytes, if successful;
     */
int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES *signature, SIZE &signlen);

int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);

/*
     * Performs RSA encryption. Returns 1 if encryption process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be encrypted;
     * inlen: size in bytes of data to be encrypted;
     * out: if successful, contains encrypted data;
     * outlen: length of encrypted data;
     * key: EVP_PKEY object of public key (create_public_RSA); 
     */
int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);

int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);

/*
     * Performs RSA decryption. Returns 1 if decryption successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be decrypted;
     * inlen: length of data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: length of decrypted data;
     * key: EVP_PKEY object of private key (create_private_RSA);
     */
int RSA_decrypt(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES *out, SIZE &outlen);