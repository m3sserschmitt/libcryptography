#include <cryptography/aes.hh>
#include <cryptography/base64.hh>
#include <cryptography/rsa.hh>
#include <cryptography/sha.hh>
#include <cryptography/random.hh>

#include <fstream>
#include <iostream>
#include <string.h>

using namespace std;

/*
static BYTES read_file(string filename, const char *open_mode)
{
    FILE *file = fopen(filename.c_str(), open_mode);

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);    
    fseek(file, 0, SEEK_SET);

    BYTES data = new BYTE[filesize + 1];

    fread(data, sizeof(BYTE), filesize, file);

    fclose(file);

    return data;
}
*/


/**
 * @brief Basic example for base64 encoding / decoding.
 * 
 * @return true if string matches decoded string.
 * @return false if final string is different from initial string.
 */
bool test_base64()
{
    BYTES data = (BYTES) "data to be encoded";
    SIZE datalen = strlen((PLAINTEXT)data);

    BASE64 encoded = 0;
    int enclen = CRYPTO::base64_encode(data, datalen, &encoded);

    cout << "encoded size: " << enclen << "\n";
    cout << "encoded data: " << encoded << "\n";

    BYTES decoded = 0;
    int declen = CRYPTO::base64_decode(encoded, &decoded);

    bool result = (int)datalen == declen and not strcmp((PLAINTEXT)data, (PLAINTEXT)decoded);

    free(encoded);
    free(decoded);

    return result;
}


/**
 * @brief Basic example for AES encryption and decryption
 * 
 * @return true if data was successfully encrypted and decrypted.
 * @return false if there were errors during the process.
 */
bool test_AES()
{
    // init AES_context.
    AES_CRYPTO ctx = CRYPTO::AES_CRYPTO_new();

    // this is data to be encrypted and its size in bytes.
    BYTES data = (BYTES) "this is text to be encrypted";
    SIZE datalen = strlen((PLAINTEXT)data);

    // encryption passphrase and its size in bytes.
    BYTES key = (BYTES) "this is encryption password";
    SIZE keylen = strlen((PLAINTEXT)key);

    // init AES context.
    cout << "AES init: " << CRYPTO::AES_init(key, keylen, 0, 128, ctx) << "\n";

    // now data can be encrypted.
    BYTES encrypted = 0;
    int enclen = CRYPTO::AES_encrypt(ctx, data, datalen, &encrypted);

    cout << "encrypted size: " << enclen << "\n";

    // decrypt data and compare final string with initial string.
    BYTES decrypted = 0;
    int decrlen = CRYPTO::AES_decrypt(ctx, encrypted, enclen, &decrypted);
    cout << "decrypted size: " << decrlen << "\n";

    cout << decrypted << "\n";

    bool result = (int)datalen == decrlen and not strcmp((PLAINTEXT)data, (PLAINTEXT)decrypted);

    free(encrypted);
    free(decrypted);

    return result;
}


/**
 * @brief Basic example for RSA encryption, decryption, signing and verification.
 * 
 * @return true if all operations succeeded.
 * @return false if errors occurred.
 */
bool test_RSA()
{
    // this is how you can generate keys.
    cout << "generate_key: " << CRYPTO::RSA_generate_keys("public.pem", "private.pem", 4096, 1, (BYTES)"private key encryption passphrase", 33, 0) << "\n";

    // create new RSA context.
    RSA_CRYPTO ctx = CRYPTO::RSA_CRYPTO_new();

    // initialize keys from generated files, then init context for encryption, decryption, signing and verification.
    cout << "pubkey init: " << CRYPTO::RSA_init_key_file("public.pem", 0, 0, PUBLIC_KEY, ctx) << "\n";
    cout << "privkey init: " << CRYPTO::RSA_init_key_file("private.pem", 0, (BYTES)"private key encryption passphrase", PRIVATE_KEY, ctx) << "\n";

    cout << "sign ctx init: " << CRYPTO::RSA_init_ctx(ctx, SIGN) << "\n";
    cout << "verify init ctx: " << CRYPTO::RSA_init_ctx(ctx, VERIFY) << "\n";

    cout << "encrypt ctx init: " << CRYPTO::RSA_init_ctx(ctx, ENCRYPT) << "\n";
    cout << "decrypt ctx init: " << CRYPTO::RSA_init_ctx(ctx, DECRYPT) << "\n";

    // data to be signed and its size in bytes.
    BYTES data = (BYTES) "text to be signed";
    SIZE datalen = strlen((PLAINTEXT)data);

    // sign data and return signature size in bytes.
    BYTES sign = 0;
    int signlen = CRYPTO::RSA_sign(ctx, data, datalen, &sign);
    cout << "signlen: " << signlen << "\n";

    bool auth;

    // verify if signature is valid.
    cout << "verify: " << CRYPTO::RSA_verify(ctx, sign, signlen, data, datalen, auth) << "\n";
    cout << "authentic: " << auth << "\n";

    // if data is changed, then the verification process should inform you about this;
    // auth2 should be set false during this process.
    bool auth2;
    cout << "verify changed data: " << CRYPTO::RSA_verify(ctx, sign, signlen, (BYTES) "changed data", 12, auth2) << "\n";
    cout << "authentic (changed data): " << auth2 << "\n";

    free(sign);

    // now test RSA encryption.
    BYTES encr = 0;
    int encrlen = CRYPTO::RSA_encrypt(ctx, data, datalen, &encr);
    
    cout << "encrlen: " << encrlen << "\n";

    // test decryption.
    BYTES decr = 0;
    int decrlen = CRYPTO::RSA_decrypt(ctx, encr, encrlen, &decr);

    cout << "decrlen: " << decrlen << "\n";
    cout << "decrypted text: " << decr << "\n";

    bool encr_result = encrlen > 0 and decr > 0 and not strcmp((PLAINTEXT)decr, (PLAINTEXT)data);

    return signlen > 0 and auth and not auth2 and encr_result;
}

int main()
{
    bool result = test_base64();

    cout << "base64 test: " << result;
    (result and cout << " (SUCCESS)\n") or cout << " (FAILURE)\n";
    cout << "\n";

    result = test_AES();

    cout << "AES test: " << result;
    (result and cout << " (SUCCESS)\n") or cout << " (FAILURE)\n";
    cout << "\n";

    result = test_RSA();

    cout << "RSA test: " << result;
    (result and cout << " (SUCCESS)\n") or cout << " (FAILURE)\n";

    return 0;
}