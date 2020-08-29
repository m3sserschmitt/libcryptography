/*
 * Cryptography class definition.
 * This class implements RSA & AES encryption / decryption, SHA256 and base64 encoding / decoding.
*/

#include "errors.h"
#include "hash.h"


#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>


#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

class Cryptography {
public:
    /*
     * Initialize Openssl library.
     */
    static void init();

    /*
     * Cleanup Openssl.
     */
    static void cleanup();

    /*
     * Calculate required memory for base64 decoding.
     * 
     * encoded_length: size of encoded data;
    */
    static size_t get_decode_length(size_t encoded_length);

    /*
     * Calculate required memory buffer for base64 decoding.
     * 
     * base64_input: base64 encoded data;
     */
    static size_t get_decode_length(char* base64_input);

    /*
     * Calculate required memory buffer for base64 encoding.
     * 
     * data_lenght: size of data to be encoded;
     */
    static size_t get_encode_length(size_t data_length);

    /*
     * Decode base64 data. Returns decoded data.
     * 
     * in: base64 data to be decoded;
     * out: decoded data size;
     */
    static unsigned char *base64_decode(std::string in, size_t &outlen);
    
    /*
     * Base64 encode. Returns encoded data.
     * 
     * in: data to be encoded;
     * length: size of data to be encoded;
     */
    static std::string base64_encode(unsigned char *in, size_t length);

    /*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * data: data to compute SHA256;
     * lenght: length of input data;
     */
    static int *compute_SHA256(unsigned char *data, size_t length);
    
    /*
     * Compute SHA256. Returns an array containing message digest.
     * 
     * data: data to compute SHA256;
     */
    static int *compute_SHA256(std::string data);
    
    /*
     * Creates a 64 bytes SHA256 hexdigest from a digest.
     * 
     * digest: digest to convert into hexdigest; 
     */
    static std::string sha256(int *digest);

    /*
     * Creates SHA256 hexdigest of provided data.
     * 
     * data: data to compute SHA256; 
     * length: data length;
     */ 
    static std::string sha256(unsigned char *data, size_t length);

    /*
     * Creates SHA256 hexdigest of input data.
     * 
     * data: data to compute SHA256; 
     */   
    static std::string sha256(std::string data);

    /*
     * Creates a EVP_PKEY private key object from PEM data.
     * 
     * private_key_pem: string containing private key in PEM format;
     */
    static EVP_PKEY* create_private_RSA(std::string private_key_pem);

    /*
     * Creates a EVP_PKEY public key object from PEM data.
     * 
     * public_key_pem: string containig public key in PEM format;
     */   
    static EVP_PKEY* create_public_RSA(std::string public_key_pem);

    /*
     * Returns public key in PEM format from EVP_PKEY public key object.
     * 
     * public_key: EVP_PKEY public key object;
     */
    static std::string get_public_PEM(EVP_PKEY *public_key);

    /*
     * Returns private key in PEM format from EVP_PKEY private key object.
     * 
     * private_key: EVP_PKEY private key object;
     */
    static std::string get_private_PEM(EVP_PKEY *private_key);

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
    static int RSA_verify_signature(EVP_PKEY* public_key, unsigned char* data_hash, size_t data_hash_length, const char* data, size_t data_length, bool &authentic);
    
    /*
     * Check authenticity of RSA signature. Returns true if verifying process successful, 
     * otherwise false.
     * 
     * public_key: EVP_PKEY object of public key (created by create_public_RSA method);
     * plain_text: message to be verified;
     * base64_signature: base64 encoded signature of provided message;
     * authentic: if successful contain result: true if valid signature, otherwise false;
     */    
    static int RSA_verify_signature(EVP_PKEY *public_key, std::string plain_text, char* base64_signature, bool &authentic);
    
    /*
     * Creates RSA signature. Returns 1 if signing process successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * private_key: EVP_PKEY object of private key (created by create_private_RSA method);
     * data: data to sign;
     * data_length: data length;
     * signature: will contain signature, if successful;
     * signature_length: will contain signature length in bytes, if successful;
     */
    static int RSA_sign(EVP_PKEY* private_key, const unsigned char* data, size_t msg_length, unsigned char *signature, size_t &signature_length);
    
    /*
     * Creates RSA signature. Returns 1 if signing process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * private_key: EVP_PKEY object of private key (created by create_private_RSA method);
     * messsage: message to be signed;
     * signature: if successful, contains base64 encoded signature of provided message;
     */    
    static int RSA_sign(EVP_PKEY *private_key, std::string message, char *signature);

    /*
     * Returns maximum size of encrypted / decrypted data for provided EVP_PKEY key object.
     * 
     * key: EVP_PKEY key object;
     */
    static int get_RSA_size(EVP_PKEY *key);

    /*
     * Get maximum size of base64 encoded RSA encrypted data for provided public key.
     * 
     * public_key: EVP_PKEY public key object.
    */
    static int get_RSA_encoded_size(EVP_PKEY *public_key);
    
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
    static int RSA_encrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *public_key);
    
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
    static int RSA_decrypt(unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen, EVP_PKEY *private_key);
    
    /*
     * Performs RSA encryption. Returns 1 if encryption process successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: data to be encrypted;
     * inlen: size in bytes of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     * public_key: EVP_PKEY object of public key (create_public_RSA); 
     */
    static int RSA_encrypt(unsigned char *in, size_t inlen, char *out, EVP_PKEY *public_key);
    
    /*
     * Performs RSA decryption. Returns 1 if decryption successful,
     * otherwise returns an appropriate negative error code.
     * 
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: length of decrypted data;
     * private_key: EVP_PKEY object of private key (create_private_RSA);
     */    
    static int RSA_decrypt(char *in, unsigned char *out, size_t &outlen, EVP_PKEY *key);
    
    /*
     * Returns size of AES encrypted data.
     * 
     * plaintext_size: size of data to be encrypted;
     */
    static size_t get_AES_encrypted_size(size_t plaintext_size);

    /*
     * Returns size of AES decrypted data.
     * 
     * ciphertext: size of encrypted data;
     */
    static size_t get_AES_decrypted_size(size_t ciphertext_size);

    /*
     * Get base64 encoded size of AES encrypted data.
     * 
     * plaintext_size: size of data to be encrypted, then base64 encoded.
    */
    static size_t get_AES_encrypted_encoded_size(size_t plaintext_size);

    /*
     * Get plaintext size of base64 encoded AES encrypeted data.
     * 
     * ciphercode_size: size of deta to be base64 decoded, then AES decrypted.
    */
    static size_t get_AES_decrypted_decoded_size(size_t ciphercode_size);

    /*
     * Initialize AES cipher key using provided key data. Returns 1 if initialization successful,
     * otherwise return an appropriate negative error code.
     * 
     * key_data: key data for key initialization;
     * key_data_length: key data length;
     * salt: salt to be used (or NULL if not desired);
     * rounds: number of SHA1 iterations;
     * key: if successful, contains initialized key;
     * iv: if successful, contains initial vector;
     */
    static int AES_cipher_key_init(unsigned char *key_data, int key_data_length, unsigned char *salt, unsigned int rounds, unsigned char *key, unsigned char *iv);
    
    /*
     * Initialize AES decryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * encrypt_ctx: AES encryption context (returned by EVP_CIPHER_CTX_new method);
     * key: AES cipher key (initialized by AES_cipher_key_init method);
     * iv: initial vector (initialized by AES_cipher_key_init method);
     */
    static int AES_encrypt_init(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *key, unsigned char *iv);
    
    /*
     * Initialize AES decryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * decrypt_ctx: AES decryption context (returned by EVP_CIPHER_CTX_new method);
     * key: AES cipher key (initialized by AES_cipher_key_init method);
     * iv: initial vector (initialized by AES_cipher_key_init method);
     */
    static int AES_decrypt_init(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *key, unsigned char *iv);
    
    /*
     * Initialize AES for encryption and decryption. Returns 1 if successful,
     * otherwise returns an appropriate negative error code.
     * 
     * key: cipher key for encrytion & decryption;
     * key_length: key length in bytes;
     * salt: salt to be used in SHA1 iterations (or null if salt not desired);
     * rounds: number of SHA1 itarations;
     * encrypt_ctx: if successful, contains encryption cipher context object;
     * decrypt_ctx: if successful, contains decryption cipher context object;
     */    
    static int AES_init(unsigned char *key, int key_length, unsigned char *salt, unsigned int rounds, EVP_CIPHER_CTX *encrypt_ctx, EVP_CIPHER_CTX *decrypt_ctx);
    
    /*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encrypt_ctx: initialized encryption context;
     * in: data to be encrypted;
     * out: if successful, contains encrypted data;
     * outlen: encrypted data length; 
     */    
    static int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen);
    
    /* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decrypt_ctx: initialized decryption context;
     * in: data to be decrypted;
     * inlen: length of data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */    
    static int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen);
    
    /*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encrypt_ctx: initialized encryption context;
     * in: data to be encrypted;
     * inlen: length of data to be encrypted;
     * out: if successful, contains base64 encoded encrypted data;
     */    
    static int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, char *out);
    
    /* 
     * Perfoms AES decryption. Returns 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * decrypt_ctx: initialized decryption context;
     * in: base64 encoded data to be decrypted;
     * out: if successful, contains decrypted data;
     * outlen: decrypted data length;
     */    
    static int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char *out, size_t &outlen);
};

#endif