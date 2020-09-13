#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>

/*
     * Returns maximum size of encrypted / decrypted data for provided EVP_PKEY key object.
     * 
     * key: EVP_PKEY key object;
     */
int get_RSA_size(EVP_PKEY *key);

/*
     * Creates a EVP_PKEY private key object from PEM data.
     * 
     * private_key_pem: string containing private key in PEM format;
     */
EVP_PKEY *create_private_RSA(std::string private_key_pem);

/*
     * Creates a EVP_PKEY public key object from PEM data.
     * 
     * public_key_pem: string containig public key in PEM format;
     */
EVP_PKEY *create_public_RSA(std::string public_key_pem);

/*
     * Returns public key in PEM format from EVP_PKEY public key object.
     * 
     * public_key: EVP_PKEY public key object;
     */
std::string get_public_PEM(EVP_PKEY *public_key);

/*
     * Returns private key in PEM format from EVP_PKEY private key object.
     * 
     * private_key: EVP_PKEY private key object;
     */
std::string get_private_PEM(EVP_PKEY *private_key);

/*
     * Check authenticity of RSA signature. Returns 1 if verifying process successful, 
     * otherwise return an appropriate negative error code.
     * 
     * public_key: EVP_PKEY object of public key (created by create_public_RSA method);
     * data_hash: signature;
     * data_hash_length: signature length;
     * data: data to check;
     * data_lenght: data length;
     * authentic: if successful contain result: true if valid signature, otherwise false;
     */
int RSA_verify_signature(EVP_PKEY *public_key, unsigned char *data_hash, size_t data_hash_length, unsigned char *data, size_t data_length, bool &authentic);

/*
     * Creates RSA signature. Returns 1 if signing process successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * private_key: EVP_PKEY object of private key (created by create_private_RSA method);
     * in: data to be signed;
     * inlen: data length;
     * signature: will contain signature, if successful;
     * signature_length: will contain signature length in bytes, if successful;
     */
int RSA_sign(EVP_PKEY *private_key, unsigned char *in, size_t inlen, unsigned char *signature, size_t &signature_length);

/*
     * Performs RSA encryption. Returns 1 if encryption process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be encrypted;
     * inlen: size in bytes of data to be encrypted;
     * out: if successful, contains encrypted data;
     * outlen: length of encrypted data;
     * public_key: RSA object of public key (create_public_RSA); 
     */
int RSA_encrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *public_key);

/*
     * Performs RSA decryption. Returns 1 if decryption successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be decrypted;
     * inlen: length of data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: length of decrypted data;
     * private_key: EVP_PKEY object of private key (create_private_RSA);
     */
int RSA_decrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *private_key);