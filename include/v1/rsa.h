#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "typedefs.h"

/*
     * Returns maximum required memory for provided KEY object.
     * 
     * key: EVP_PKEY key object;
     */
int get_RSA_size(KEY key);

/*
     * Creates a EVP_PKEY private key object from PEM data.
     * 
     * key_pem: string containing private key in PEM format;
     */
PRIVATE_KEY create_private_RSA(std::string key_pem);

/*
     * Creates a EVP_PKEY public key object from PEM data.
     * 
     * key_pem: string containig public key in PEM format;
     */
PUBLIC_KEY create_public_RSA(std::string key_pem);

/*
     * Free public / private key.
     * 
     * key: key to be freed;
     */
void RSA_free_key(KEY key);

/*
     * Returns public key in PEM format from EVP_PKEY public key object.
     * 
     * key: EVP_PKEY public key object;
     */
std::string get_public_PEM(PUBLIC_KEY key);

/*
     * Returns private key in PEM format from EVP_PKEY private key object.
     * 
     * key: EVP_PKEY private key object;
     */
std::string get_private_PEM(PRIVATE_KEY key);

/*
     * Check authenticity of RSA signature. Returns 1 if verifying process successful, 
     * otherwise return an appropriate negative error code.
     * 
     * key: EVP_PKEY object of public key (created by create_public_RSA method);
     * hash: signature;
     * hashlen: signature length;
     * data: data to check;
     * datalen: data length;
     * authentic: if successful contain result: true if valid signature, otherwise false;
     */
int RSA_verify_signature(PUBLIC_KEY key, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic);

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
int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen);

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
int RSA_encrypt(BYTES in, SIZE inlen, BYTES out, SIZE &outlen, PUBLIC_KEY key);

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
int RSA_decrypt(BYTES in, SIZE inlen, BYTES out, SIZE &outlen, PRIVATE_KEY key);

#ifndef RSA_H_1
#define RSA_H_1

#define RSA_get_size(key) get_RSA_size(key)
#define RSA_create_private_key(key_pem) create_private_RSA(key_pem)
#define RSA_create_public_key(key_pem) create_public_RSA(key_pem)
#define RSA_get_public_PEM(key) get_public_PEM(key)
#define RSA_get_private_PEM(key) get_private_PEM(key)

#endif