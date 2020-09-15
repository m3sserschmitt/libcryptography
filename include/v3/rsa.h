#include "../v2/rsa.h"

/*
     * Get maximum size of base64 encoded RSA for provided key.
     * 
     * key: EVP_PKEY object.
    */
int get_RSA_encoded_size(KEY key);

/*
     * Creates RSA signature. Returns 1 if signing process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * key: EVP_PKEY object of private key (created by create_private_RSA method);
     * in: data to be signed;
     * inlen: size of data;
     * signature: if successful, contains base64 encoded signature of provided message;
     */
int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BASE64 signature);

/*
     * Check authenticity of RSA signature. Returns true if verifying process successful, 
     * otherwise false.
     * 
     * key: EVP_PKEY object of public key (created by create_public_RSA method);
     * in: data to be verified;
     * inlen: size of data;
     * signature: base64 encoded signature of input data;
     * authentic: if successful contain result: true if valid signature, otherwise false;
     */
int RSA_verify_signature(PUBLIC_KEY key, BYTES in, SIZE inlen, BASE64 signature, bool &authentic);

/*
     * Performs RSA encryption. Returns 1 if encryption process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be encrypted;
     * inlen: size in bytes of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     * key: EVP_PKEY object of public key (create_public_RSA); 
     */
int RSA_encrypt(BYTES in, SIZE inlen, BASE64 out, PUBLIC_KEY key);

/*
     * Performs RSA decryption. Returns 1 if decryption successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: length of decrypted data;
     * key: EVP_PKEY object of private key (create_private_RSA);
     */
int RSA_decrypt(BASE64 in, BYTES out, SIZE &outlen, PRIVATE_KEY key);

#ifndef RSA_H
#define RSA_H

#define RSA_get_encoded_size(key) get_RSA_encoded_size(key)

#endif