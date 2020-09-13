#include "../v1/rsa.h"

/*
     * Get maximum size of base64 encoded RSA encrypted data for provided public key.
     * 
     * public_key: EVP_PKEY public key object.
    */
int get_RSA_encoded_size(EVP_PKEY *public_key);

/*
     * Creates RSA signature. Returns 1 if signing process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * private_key: EVP_PKEY object of private key (created by create_private_RSA method);
     * in: data to be signed;
     * inlen: size of data;
     * signature: if successful, contains base64 encoded signature of provided message;
     */
int RSA_sign(EVP_PKEY *private_key, unsigned char *in, size_t inlen, char *signature);

/*
     * Check authenticity of RSA signature. Returns true if verifying process successful, 
     * otherwise false.
     * 
     * public_key: EVP_PKEY object of public key (created by create_public_RSA method);
     * in: data to be verified;
     * inlen: size of data;
     * signature: base64 encoded signature of input data;
     * authentic: if successful contain result: true if valid signature, otherwise false;
     */
int RSA_verify_signature(EVP_PKEY *public_key, unsigned char *in, size_t inlen, char *signature, bool &authentic);

/*
     * Performs RSA encryption. Returns 1 if encryption process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be encrypted;
     * inlen: size in bytes of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     * public_key: EVP_PKEY object of public key (create_public_RSA); 
     */
int RSA_encrypt(unsigned char *in, size_t inlen, char *out, EVP_PKEY *public_key);

/*
     * Performs RSA decryption. Returns 1 if decryption successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: length of decrypted data;
     * private_key: EVP_PKEY object of private key (create_private_RSA);
     */
int RSA_decrypt(char *in, unsigned char *out, size_t &outlen, EVP_PKEY *key);