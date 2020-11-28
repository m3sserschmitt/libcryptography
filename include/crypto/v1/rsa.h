/** \file rsa.h
 * \brief RSA encryption, decryption, signing & verification.
 */

#include <string>


#include "typedefs.h"

/**
 * Returns maximum required memory for provided KEY object.
 * 
 * @param key: key object;
 */
int RSA_get_size(KEY key);

/**
 * Creates a PRIVATE_KEY object from PEM data.
 * 
 * @param key_pem: string containing private key in PEM format;
 */
PRIVATE_KEY RSA_create_private_key(std::string key_pem);

/**
 * Creates a PUBLIC_KEY object from PEM data.
 * 
 * @param key_pem: string containig public key in PEM format;
 */
PUBLIC_KEY RSA_create_public_key(std::string key_pem);

/**
 * Create SIGN_CONTEXT from PRIVATE_KEY object;
 * 
 * @param key: PRIVATE_KEY instance used to create SIGN_CONTEXT;
 */
SIGN_CONTEXT RSA_create_sign_ctx(PRIVATE_KEY key);

/**
 * Create VERIFY_CONTEXT from PUBLIC_KEY instance.
 * 
 * @param key: PUBLIC_KEY instance used to create VERIFY_CONTEXT;
 */
VERIFY_CONTEXT RSA_create_verify_ctx(PUBLIC_KEY key);

/**
 * Create RSA_ENCRYP_CONTEXT instance for encryption operations.
 * 
 * @param key: PUBLIC_KEY instance used to create RSA_ENCRYPT_CONTEXT;
 */
RSA_ENCRYPT_CONTEXT RSA_create_encrypt_ctx(PUBLIC_KEY key);

/**
 * Create RSA_DECRYPT_CONTEXT instance for decryption operations.
 * 
 * @param key: PRIVATE_KEY instance used to create RSA_DECRYPT_CONTEXT;
 */
RSA_DECRYPT_CONTEXT RSA_create_decrypt_ctx(PRIVATE_KEY key);

/**
 * Free public / private key.
 * 
 * @param key: key to be freed;
 */
void RSA_free_key(KEY key);

/**
 * Frees SIGN_CONTEXT instance created by RSA_create_sing_ctx.
 * 
 * @param ctx: context to be freed;
 */
void RSA_free_sign_ctx(SIGN_CONTEXT ctx);

/**
 * Frees VERIFY_CONTEXT instance created by RSA_create_sign_ctx.
 * 
 * @param ctx: context to be breed;
 */
void RSA_free_verify_ctx(VERIFY_CONTEXT ctx);

/**
 * Frees RSA_PKEY_CONTEXT instance.
 * 
 * @param ctx: RSA_ENCRYPT_CONTEXT or RSA_DECRYPT_CONTEXT instance previously created
 * by RSA_create_encrypt_ctx or RSA_create_decrypt_ctx;
 */
void RSA_free_context(RSA_PKEY_CONTEXT ctx);

/**
 * Returns public key in PEM format from PUBLIC_KEY instance.
 * 
 * @param key: PUBLIC_KEY instance;
 */
std::string RSA_get_public_PEM(PUBLIC_KEY key);

/**
 * Returns private key in PEM format from PRIVATE_KEY instance.
 * 
 * @param key: PRIVATE_KEY instance;
 */
std::string RSA_get_private_PEM(PRIVATE_KEY key);

/**
 * Creates RSA signature. Returns 1 if signing process successful, 
 * otherwise returns an appropriate negative error code.
 * 
 * @param ctx: SIGN_CONTEXT instance (created by RSA_create_sign_ctx);
 * @param in: data to be signed;
 * @param inlen: data length;
 * @param signature: will contain signature, if successful;
 * @param signlen: will contain signature length in bytes, if successful;
 */
int RSA_sign(SIGN_CONTEXT ctx, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen);

/**
 * Creates RSA signature. Returns 1 if signing process successful, 
 * otherwise returns an appropriate negative error code.
 * 
 * @param key: PRIVATE_KEY instance (created by RSA_create_private_key);
 * @param in: data to be signed;
 * @param inlen: data length;
 * @param signature: will contain signature, if successful;
 * @param signlen: will contain signature length in bytes, if successful;
 */
int RSA_sign(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES signature, SIZE &signlen);

/**
 * Check authenticity of RSA signature. Returns 1 if verifying process successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param ctx: VERIFY_CONTEXT instance (created by RSA_create_verify_ctx);
 * @param hash: signature;
 * @param hashlen: signature length;
 * @param data: data to check;
 * @param datalen: data length;
 * @param authentic: if successful contain result  true if valid signature, otherwise false;
 */
int RSA_verify_signature(VERIFY_CONTEXT ctx, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic);

/**
 * Check authenticity of RSA signature. Returns 1 if verifying process successful, 
 * otherwise return an appropriate negative error code.
 * 
 * @param key: PUBLIC_KEY instance (created by RSA_create_public_key);
 * @param hash: signature;
 * @param hashlen: signature length;
 * @param data: data to check;
 * @param datalen: data length;
 * @param authentic: if successful contain result: true if valid signature, otherwise false;
 */
int RSA_verify_signature(PUBLIC_KEY key, BYTES hash, SIZE hashlen, BYTES data, SIZE datalen, bool &authentic);

/**
 * Performs RSA encryption. Returns 1 if encryption process successful,
 * otherwise returns an appropriate negative error code.
 * 
 * @param ctx: RSA_ENCRYPT_CONTEXT instance (created by RSA_create_encrypt_ctx); 
 * @param in: data to be encrypted;
 * @param inlen: size in bytes of data to be encrypted;
 * @param out: if successful, contains encrypted data;
 * @param outlen: length of encrypted data;
 */
int RSA_encrypt(RSA_ENCRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);

/**
 * Performs RSA encryption. Returns 1 if encryption process successful,
 * otherwise returns an appropriate negative error code.
 * 
 * @param key: PUBLIC_KEY instance (created by RSA_create_public_key); 
 * @param in: data to be encrypted;
 * @param inlen: size in bytes of data to be encrypted;
 * @param out: if successful, contains encrypted data;
 * @param outlen: length of encrypted data;
 */
int RSA_encrypt(PUBLIC_KEY key, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);

/**
 * Performs RSA decryption. Returns 1 if decryption successful,
 * otherwise returns an appropriate negative error code.
 * 
 * @param ctx: RSA_DECRYPT_CONTEXT instance (created by RSA_create_decrypt_ctx);
 * @param in: data to be decrypted;
 * @param inlen: length of data to be decrypted;
 * @param out: if successful, contains decrypted data;
 * @param outlen: length of decrypted data;
 */
int RSA_decrypt(RSA_DECRYPT_CONTEXT ctx, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);

/**
 * Performs RSA decryption. Returns 1 if decryption successful,
 * otherwise returns an appropriate negative error code.
 * 
 * @param key: PRIVATE_KEY instance (created by RSA_create_private_key);
 * @param in: data to be decrypted;
 * @param inlen: length of data to be decrypted;
 * @param out: if successful, contains decrypted data;
 * @param outlen: length of decrypted data;
 */
int RSA_decrypt(PRIVATE_KEY key, BYTES in, SIZE inlen, BYTES out, SIZE &outlen);
