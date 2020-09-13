#include <openssl/evp.h>
#include <openssl/aes.h>

/*
     * Returns size of AES encrypted data.
     * 
     * inlen: size of data to be encrypted;
     */
size_t get_AES_encrypted_size(size_t inlen);

/*
     * Returns size of AES decrypted data.
     * 
     * ciphertext: size of encrypted data;
     */
size_t get_AES_decrypted_size(size_t ciphertext_size);

/*
     * Initialize AES decryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * encrypt_ctx: AES encryption context (returned by EVP_CIPHER_CTX_new method);
     * key_data: AES cipher key;
     * keylen: size of key;
     * salt: salt to be used in sha256 iterations;
     * rounds: number of sha256 iterations;
     */
int AES_encrypt_init(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *key_data, size_t keylen, unsigned char *salt, int rounds);

/*
     * Initialize AES decryption context. Returns 1 if initialization successful, 
     * otherwise returns an appropriate negative error code.
     * 
     * decrypt_ctx: AES decryption context (returned by EVP_CIPHER_CTX_new method);
     * key_data: AES cipher key;
     * keylen: size of key;
     * salt: salt to be used in sha256 iterations;
     * rounds: number of sha256 iterations;
     */
int AES_decrypt_init(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *key_data, size_t keylen, unsigned char *salt, int rounds);

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
int AES_init(unsigned char *key, int key_length, unsigned char *salt, unsigned int rounds, EVP_CIPHER_CTX *encrypt_ctx, EVP_CIPHER_CTX *decrypt_ctx);

/*
     * Performs AES encryption. Return 1 if successful, otherwise returns an appropriate
     * negative error code.
     * 
     * encrypt_ctx: initialized encryption context;
     * in: data to be encrypted;
     * out: if successful, contains encrypted data;
     * outlen: encrypted data length; 
     */
int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen);

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
int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, unsigned char *in, size_t inlen, unsigned char *out, size_t &outlen);