/**
 * \file typedefs.h
 * \brief Data types definitions.
*/

#include <cstddef>
#include <openssl/evp.h>


#ifndef TYPEDEFS_H
#define TYPEDEFS_H

/// Store one byte.
typedef unsigned char BYTE; 

/// Pointer to array containing binary data.
typedef BYTE *BYTES; 

/// Pointer to plaintext data (printable characters).
typedef char *PLAINTEXT;

/// Pointer to plaintext base64 encoded data.
typedef PLAINTEXT BASE64;

/// Pointer to an array containing a message digest.
typedef int *DIGEST;

/// Store size of data.
typedef size_t SIZE;

/* |======================================|
 * |========= AES ciphers types ==========|
 * |======================================|
*/

/// Pointer to AES encryption / decryption cipher context.
typedef EVP_CIPHER_CTX *CIPHER_CONTEXT;

/// Instance of AES decryption cipher context. 
typedef CIPHER_CONTEXT DECRYPT_CONTEXT;

/// Instance of AES encryption cipher context.
typedef CIPHER_CONTEXT ENCRYPT_CONTEXT;

/* |============================================|
 * |====== Hash types (signing contexts) =======|
 * |============================================|
*/ 

/// Pointer to RSA signing / verification context.
typedef EVP_MD_CTX *MD_CONTEXT;

/// Instance of RSA verify context.
typedef MD_CONTEXT VERIFY_CONTEXT;

/// Structure containing signing context, key length and maximum output length.
typedef struct
{
    MD_CONTEXT sign_ctx; //!< Signing context.
    SIZE bits; //!< Key lenght in bits.
    SIZE maxlen; //!< Maximum length of signature in bytes. 
} SIGN_CTX;

/// Instance of extended RSA signing context.
typedef SIGN_CTX *SIGN_CONTEXT;

/* |================================================================|
 * |============ Public & private key cryptography types ===========|
 * |================================================================|
*/

/// Pointer to RSA key (public or private).
typedef EVP_PKEY *KEY;

/// Instance of RSA public key.
typedef KEY PUBLIC_KEY;

/// Instance of RSA private key.
typedef KEY PRIVATE_KEY;

/// Pointer to RSA encryption / decryption context.
typedef EVP_PKEY_CTX *PKEY_CONTEXT;

/// Structure containing RSA encryption / decryption context, key length & maximum output length.
typedef struct
{
    PKEY_CONTEXT ctx; //!< RSA public / private key context for encryption / decryption.
    SIZE bits; //!< Length of key in bits.
    SIZE maxlen; //!< Maximum size of encrypted / decrypted data, in bytes.
} RSA_PKEY_CTX;

/// Instance of extended RSA encryption / decryption context. 
typedef RSA_PKEY_CTX *RSA_PKEY_CONTEXT;

/// Instance of extended RSA encryption context.
typedef RSA_PKEY_CONTEXT RSA_ENCRYPT_CONTEXT;

/// Instance of extended RSA decryption context.
typedef RSA_PKEY_CONTEXT RSA_DECRYPT_CONTEXT;

#endif