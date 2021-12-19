/**
 * @file aes.hh
 * @author Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>
 * @brief This file contains functions for basic AES operations.
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */

#ifndef AES_HH
#define AES_HH

#include "types.hh"
#include "aes_const.hh"

namespace CRYPTO
{
  /**
 * @brief Create new AES encryption / decryption context.
 * 
 * @return AES_CRYPTO AES encryption / decryption context.
 */
  AES_CRYPTO AES_CRYPTO_new();

  /**
 * @brief Setup key to be used for AES encryption / decryption.
 * 
 * @param key Key to be used.
 * @param ctx AES context to setup encryption key.
 * @return int 0 if success, -1 if failure.
 */
  int AES_setup_key(const BYTE *key, SIZE keylen, AES_CRYPTO ctx);

  /**
 * @brief Enable or disable IV autoset. If IV autoset enabled, then a new IV is generated on every encryption cycle.
 * 
 * @param autoset IV autoset flag
 * @param ctx AES to enable IV autoset
 */
  [[deprecated("This function might be removed in further releases; AES_auth_encrypt will automatically generate a new IV on every encryption cycle.")]] void AES_iv_autoset(bool autoset, AES_CRYPTO ctx);

  /**
 * @brief Enable or disable IV append. If IV append enabled, then IV will be put at the beginning of every ciphertext.
 * 
 * @param append IV append flag
 * @param ctx AES to enable IV append
 */
  [[deprecated("This function might be removed in further releases; AES_auth_encrypt will automatically append IV to ciphertext")]] void AES_iv_append(bool append, AES_CRYPTO ctx);

  /**
 * @brief Setup initialization vector to be used for encryption / decryption.
 * 
 * @param iv Initialization vector (tipically a 16 bytes random vector).
 * @param ctx AES context to setup iv vector.
 * @return int 0 if success, -1 if failure.
 */
  int AES_setup_iv(const BYTE *iv, SIZE ivlen, AES_CRYPTO ctx);

  /**
 * @brief Return current encryption key from AES context.
 * 
 * @param ctx Context to retrieve key from.
 * @return SIZE return length of key in bytes.
 */
  int AES_read_key(const _AES_CRYPTO *ctx, SIZE keylen, BYTES *key);

  /**
 * @brief Get initialization vector from AES context.
 * 
 * @param ctx Context to retrieve iv from.
 * @return SIZE Size of iv in bytes or -1 if no iv is used within this context.
 */
  int AES_read_iv(const _AES_CRYPTO *ctx, SIZE ivlen, BYTES *iv);

  /**
    * @brief Initialize AES contex for specified operation.
    * 
    * @param op Cryptographic operation: ENCRYPT / DECRYPT.
    * @param ctx AES context to be initialized.
    * @return int 
    */
  int AES_init_ctx(CRYPTO_OP op, AES_CRYPTO ctx);

  /**
 * @brief Initialize AES contex for specified operation.
 * 
 * @param passphrase Passphrase to be used for encryption.
 * @param passlen Length of passphrase in bytes.
 * @param salt Salt to be used (or null in not desired).
 * @param rounds Number of encryption rounds.
 * @param op Cryptographic operation: ENCRYPT / DECRYPT.
 * @param ctx AES context to be initialized.
 * @return int 0 for success, -1 for failure.
 */
  [[deprecated("This function initializes AES context in CBC mode and it might be removed in further releases. Use AES_setup key & AES_init_ctx instead.")]] int AES_init(const BYTE *passphrase, SIZE passlen, const BYTE *salt, int rounds, CRYPTO_OP op, AES_CRYPTO ctx);

  /**
 * @brief Initialize AES context for both encryption and decryption.
 * 
 * @param passphrase Passphrase to be used for encryption.
 * @param passlen Length of passphrase in bytes.
 * @param salt Salt to be used. It should point to an 8 byte buffer or NULL if no salt is used.
 * @param rounds Number of iteration count to use. Increasing the count parameter slows down the 
 * algorithm which makes it harder for an attacker to perform a brute force attack using a large number of candidate passwords.
 * @param ctx AES context to be initialized.
 * @return int 0 for success, -1 for failure.
 */
  [[deprecated("This function initializes AES context in CBC mode and it might be removed in further releases. Use AES_setup key & AES_init_ctx instead.")]] int AES_init(const BYTE *passphrase, SIZE passlen, const BYTE *salt, int rounds, AES_CRYPTO ctx);

  /**
 * @brief Check if AES context is ready for encryption;
 * 
 * @param ctx AES context to be checked
 * @return int 1 if AES context is ready for encryption, 0 otherwise
 */
  int AES_encrypt_ready(const _AES_CRYPTO *ctx);

  /**
 * @brief Check if AES context is ready for decryption;
 * 
 * @param ctx AES context to be checked
 * @return int 1 if AES context is ready for decryption, 0 otherwise
 */
  int AES_decrypt_ready(const _AES_CRYPTO *ctx);

  /**
 * @brief Duplicates AES context. Destination context will use the same resources as source context.
 * For example, if you clean up destination context, source context will be freed too.
 * This function is used when you want to encrypt / decrypt using different keys, but you don't want to allocate 
 * a new context;
 * 
 * @param dest Destination AES context.
 * @param src Source AES context.
 * @return int 0 if success, -1 if failure.
 */
  int AES_ctx_dup(AES_CRYPTO dest, const _AES_CRYPTO *src);

  /**
 * @brief Perform AES encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @param aad Additional Authenticated Data (AAD)
 * @param aadlen Additional authenticated data size in bytes
 * @return int Size of encrypted data if success, -1 if failure.
 */
  int AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out);

  /**
 * @brief Perform AES encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @return int Size of encrypted data if success, -1 if failure.
 */
  int AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Perform AES encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @return int Size of encrypted data if success, -1 if failure.
 */
  [[deprecated("This function uses CBC mode for encryption and might be removed in further releases; Use AES_auth_encrypt instead.")]] int AES_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Perform AES encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @param aad Additional Authenticated Data (AAD)
 * @param aadlen Additional authenticated data size in bytes
 * @return int Size of encrypted data if success, -1 if failure.
 */
  int AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out);

  /**
 * @brief Perform AES decryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be decrypted.
 * @param inlen Data length in bytes.
 * @param out Decrypted data (if null, then it is dynamically allocated).
 * @return int Size of decrypted data if success, -1 if failure.
 */
  int AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Perform AES decryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be decrypted.
 * @param inlen Data length in bytes.
 * @param out Decrypted data (if null, then it is dynamically allocated).
 * @return int Size of decrypted data if success, -1 if failure.
 */
  [[deprecated("This function uses CBC mode for decryption and might be removed in further releases; Use AES_auth_decrypt instead.")]] int AES_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Frees memory allocated for AES context.
 * 
 * @param ctx Context to be freed.
 */
  void AES_CRYPTO_free(AES_CRYPTO ctx);

  void AES_CRYPTO_free_keys(AES_CRYPTO ctx);
}

#endif
