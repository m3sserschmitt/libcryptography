/**
 * @file rsa.hh
 * @author Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>
 * @brief This file contains functions for basic RSA operations.
 * @date 2021-07-06
 * 
 * @copyright Copyright (c) 2021 MIT License.
 * 
 */

#ifndef RSA_HH
#define RSA_HH

#include "types.hh"

#include <string>

namespace CRYPTO
{

  /**
 * @brief Password Callback.
 * 
 * @param buf Buffer to write the passphrase to.
 * @param size Size of buff (i.e password length).
 * @param rw A typical routine will ask the user to verify the passphrase (for example by prompting for it twice) if rw is 1.
 * @param userdata It allows arbitrary data to be passed to the callback by the application.
 * @return int The callback MUST return the number of characters in the passphrase or -1 if an error occurred.
 */
  typedef int password_cb(char *buf, int size, int rw, void *userdata);

  /**
 * @brief Create new RSA encryption / decryption context.
 * 
 * @return RSA_CRYPTO RSA context for encryption / decryption. 
 */
  RSA_CRYPTO RSA_CRYPTO_new();

  /**
 * @brief 
 * 
 * @param public_key File for saving public key.
 * @param private_key File for saving private key.
 * @param bits Key length in bits
 * @param encrypt_key Should be true if key encryption desired, otherwise false.
 * @param passphrase Passphrase for private key encryption (if null, then private key will be saved unencrypted)
 * @param passlen Passphrase length in bytes.
 * @param cb Callback function used to read encryption passphrase. If null, then default callback is used. This callback is
 * used only when key encryption desired and passphrase parameter is null.
 * @return int 0 if success, -1 if failure.
 */
  int RSA_generate_keys(
      const std::string &public_key,
      const std::string &private_key,
      SIZE bits,
      bool encrypt_key,
      BYTE *passphrase,
      SIZE passlen,
      password_cb *cb);

  /**
 * @brief Perform key initialization.
 * 
 * @param PEM Key in PEM format.
 * @param cb Callback function used to read decryption passphrase, if key is encrypted. If null, then default callback is used.
 * This callback is used only when key is encrypted and passphrase parameter is null.
 * @param passphrase It can be used as key decryption passphrase, or null if passphrase not required
 * If not null, then the callback provided in cb parameter is ignored.
 * @param ktype Key type: PUBLIC_KEY / PRIVATE_KEY
 * @param ctx Should be created with RSA_CRYPTO_new function.
 * @return int 0 for success, -1 for failure.
 */
  int RSA_init_key(
      const std::string &PEM,
      password_cb *cb,
      BYTE *passphrase,
      KEY_TYPE ktype,
      RSA_CRYPTO ctx);

  /**
 * @brief Initialize RSA key from PEM file.
 * 
 * @param filename File path containing key in PEM format.
 * @param cb Password callback used to read decryption passphrase, if key is encrypted. If null, then default callback is used.
 * If passphrase parameter is not null, then cb is ignored.
 * @param passphrase Passphrase for key decryption, if required, otherwise null.
 * @param ktype Type of key: PUBLIC_KEY / PRIVATE_KEY.
 * @param ctx RSA context to be initialized (must be returned by RSA_CRYPTO_new function).
 * @return int 0 if success, -1 if failure.
 */
  int RSA_init_key_file(
      const std::string &filename,
      password_cb *cb,
      BYTE *passphrase,
      KEY_TYPE ktype,
      RSA_CRYPTO ctx);

  int RSA_pubkey_ready(const _RSA_CRYPTO *ctx);
  int RSA_privkey_ready(const _RSA_CRYPTO *ctx);

  /**
 * @brief Perform RSA context initialization. First of all you should initialize the key using RSA_init_key 
 * (e.g. for RSA encryption, you should call RSA_init_key with a valid public key in PEM format and appropriate parameters).
 * 
 * @param ctx RSA context to be initialized.
 * @param op Required RSA operation: ENCRYPT / DECRYPT / SIGN / VERIFY.
 * @return int 0 for success, -1 if failure.
 */
  int RSA_init_ctx(RSA_CRYPTO ctx, CRYPTO_OP op);
  int RSA_encrypt_ready(const _RSA_CRYPTO *ctx);
  int RSA_decrypt_ready(const _RSA_CRYPTO *ctx);
  int RSA_sign_ready(const _RSA_CRYPTO *ctx);
  int RSA_verify_ready(const _RSA_CRYPTO *ctx);
  /**
 * @brief Perform PEM to DER conversion (basically it removes key header and then performs base64 decoding).
 * 
 * @param PEM PEM to be converted.
 * @param der DER data (if null, then is is dynamically allocated).
 * @return int Size of DER data if success, -1 otherwise.
 */
  // int PEM_key_to_DER(RSA_CRYPTO ctx, BYTES *der);

  /**
 * @brief Perform RSA signing.
 * 
 * @param ctx RSA context initialized accordingly.
 * @param in Data to be signed.
 * @param inlen Size of data in bytes.
 * @param sign RSA signature (if null, then is dynamically allocated).
 * @return int Size of signature if success, -1 otherwise.
 */
  int RSA_sign(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *sign);

  /**
 * @brief Performs RSA signature verification.
 * 
 * @param ctx RSA context initialized accordingly.
 * @param sign Signature to be verified.
 * @param signlen Signature size in bytes.
 * @param data Signed data.
 * @param datalen Signed data size in bytes.
 * @param auth Verification result.
 * @return int 0 for success, -1 if failure.
 */
  int RSA_verify(
      RSA_CRYPTO ctx,
      const BYTE *sign,
      SIZE signlen,
      const BYTE *data,
      SIZE datalen,
      bool &auth);

  /**
 * @brief Perform RSA encryption.
 * 
 * @param ctx RSA context initialized accordingly.
 * @param in Data to be encrypted.
 * @param inlen Size of data ti be encrypted in bytes.
 * @param out Encrypted data (if null, then is dynamically allocated).
 * @return int Size of encrypted data if success, -1 otherwise.
 */
  int RSA_encrypt(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Perform RSA decryption.
 * 
 * @param ctx RSA context initialized accordingly.
 * @param in Data to be decrypted.
 * @param inlen Size of data to be decrypted in bytes.
 * @param out Decrypted data (if null, then is dynamically allocated).
 * @return int Size of decrypted data if success, -1 otherwise.
 */
  int RSA_decrypt(RSA_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

  /**
 * @brief Frees memory allocated for RSA context.
 * 
 * @param ctx Context to be freed.
 */
  void RSA_CRYPTO_free(RSA_CRYPTO ctx);
}

#endif
