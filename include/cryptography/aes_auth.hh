/**
 * @file aes_auth.hh
 * @author Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>
 * @brief This file contains function definitions for AES GCM
 * @date 2021-12-19
 * 
 * @copyright Copyright (c) 2021 MIT License
 * 
 */


#include "aes_const.hh"
#include "types.hh"


namespace CRYPTO
{
   /**
 * @brief Perform AES GCM encryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be encrypted.
 * @param inlen Data length in bytes.
 * @param out Encrypted data (if null, then it is dynamically allocated).
 * @param aad Additional Authenticated Data (AAD)
 * @param aadlen Additional authenticated data size in bytes
 * @return int Size of encrypted data if success, -1 if failure.
 */
   int AES_auth_encrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);

   /**
 * @brief Perform AES GCM encryption.
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
 * @brief Perform AES GCM decryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be decrypted.
 * @param inlen Data length in bytes.
 * @param out Decrypted data (if null, then it is dynamically allocated).
 * @param aad Additional Authenticated Data (AAD)
 * @param aadlen Additional authenticated data size in bytes
 * @return int Size of decrypted data if success, -1 if failure.
 */
   int AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, const BYTE *aad, SIZE aadlen, BYTES *out);

   /**
 * @brief Perform AES GCM decryption.
 * 
 * @param ctx Initialized AES context.
 * @param in Data to be decrypted.
 * @param inlen Data length in bytes.
 * @param out Decrypted data (if null, then it is dynamically allocated).
 * @return int Size of decrypted data if success, -1 if failure.
 */
   int AES_auth_decrypt(AES_CRYPTO ctx, const BYTE *in, SIZE inlen, BYTES *out);
}
