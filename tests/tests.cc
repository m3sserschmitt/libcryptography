#include <crypto/cryptography.h>
#include <crypto/mem.h>

#include <string.h>
#include <iostream>

using namespace std;

string public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojYb5h0vm9YEK5sDO6fJ\n"
                        "CH0qFik8p7yB2XTqA0rj1v52+trmMWxI5X3JmFUCMr+vx+kiwBTcud4AwrvkcV3o\n"
                        "4Vi4zgr/UbV04D1VddCGxrTPkelKqKbQCYPIVtzJ5ZJtPBPaCgoBHgy9K/wYIfnS\n"
                        "77ybULYJFFDKEgcI6sjPlYg/PTYQKzsqRRYE2Ec/ctALOWL56ZA31pkdih9xhuID\n"
                        "gon4el4s31oaAoUHaF7eUR8iWIjvFMsdzm8GSYvZJTkQzMy9YiSrQUXhNXzOiV1P\n"
                        "A9cp8YQ2KaB1f5Tj648c9TaChdwzA+5MZPUmeQve+stwm8h+CreIMbiRAQ2Mf0HU\n"
                        "OQIDAQAB\n"
                        "-----END PUBLIC KEY-----";

string private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                         "MIIEowIBAAKCAQEAojYb5h0vm9YEK5sDO6fJCH0qFik8p7yB2XTqA0rj1v52+trm\n"
                         "MWxI5X3JmFUCMr+vx+kiwBTcud4AwrvkcV3o4Vi4zgr/UbV04D1VddCGxrTPkelK\n"
                         "qKbQCYPIVtzJ5ZJtPBPaCgoBHgy9K/wYIfnS77ybULYJFFDKEgcI6sjPlYg/PTYQ\n"
                         "KzsqRRYE2Ec/ctALOWL56ZA31pkdih9xhuIDgon4el4s31oaAoUHaF7eUR8iWIjv\n"
                         "FMsdzm8GSYvZJTkQzMy9YiSrQUXhNXzOiV1PA9cp8YQ2KaB1f5Tj648c9TaChdwz\n"
                         "A+5MZPUmeQve+stwm8h+CreIMbiRAQ2Mf0HUOQIDAQABAoIBAANpI9kI0BF0xI2u\n"
                         "Krk8Y+u7xgDFSTM1sX1DChCbqILCwvmvVJvBbR72MCD12J/8i9OmQUbMqX92/Yka\n"
                         "rkj78oOae/hJHuk26Yg1gfCCO/M9pgepYhp9t24byUCaT9x14bobqMABSdi559he\n"
                         "6pr8R8UmsBVYXoSA1l7eqv9UzZiVRjm1b+j1W5BhB2D2Y5WaclVO/8oPinVQ72fl\n"
                         "9oHrgZwvchiy2f69H/puXU/tnbjlvGN+5JSSizlipMvXALU9RJ2leo+jGRlbvPnT\n"
                         "m0fDS8TrPyeh5DOTiFpS4HI1YFFHvWOyt2ixsnm1PqZ8UTTpSfx8SAJJOR+0i40q\n"
                         "HouyXQECgYEA184Cq1bG8ZBHf9uFCNTBq5JL84gJpC1AZ6eh0otPv6LdrzbfsOkR\n"
                         "P4+BEE81HuxodeK+3Gmz22Pj6EEBJBNm252ybj6AZI4c4oCghaioXhWA2ECv49jh\n"
                         "cYV81W3sd2tv+Z2P6YNctAR9mPMbJEwUyvu4zuES/+xNQ+ghGpVqfpECgYEAwGyp\n"
                         "nljc5wN3P+FOjwxm0KZ4ihXac4x6Yz7Ay/Zd9qXi2iR6o8tZEYWHiuwIX2/1+GZR\n"
                         "Tdg2ItjrUNimGbcqqg2lOz1XmXiruDE495/zE9Eq1W3BZzilBR5HGc6quRvJAuGX\n"
                         "IplB3ZifnS2z2glHwee4piPXLFM6ZO5BlZ3gHykCgYBfKR2uNjbF4IxWyhMQwNih\n"
                         "8oIBYnR16+phit7lu76vz36Xu8fJ+Aw+DeaorXTMLQ0nJpRpF0dTL+oYyUlagh+y\n"
                         "Kgi7al4teSkti/C835FW436MXYHyI/nNmEJizvUd98dJt/v0yZNAYlaL8m9+gvoM\n"
                         "RBHLUB6TsbykfCDU2xw5sQKBgQCPhHw+Dik0Y/FdQ75EEwvcM01UMFhuNihSPUuu\n"
                         "1GHgxHkeGnceE1yrJNyjUMgt5mOekTGyzcAS3ZclBXFdXLAFhYfnVyku3kG1b4D9\n"
                         "r96suSUpamMFicoKtzpwlSPgTEjwTTFcLNJjZKInqR6rUKCkjx+5SqIB/VFgVhO0\n"
                         "c7vlgQKBgDje/M4XEcjXmi3O21zkl7sC0I7em9T9VSXKBZyOe0/dzVokdo94kP8m\n"
                         "6MlKDvP9655xB5GMwgp8w1GDP2xKmGcfUeDPuoZrbIlNTn2OBsSNNVXmRgbJrhGv\n"
                         "rC7HYscrIl9BW+3y+NPPJx/+ElDymXVDlrUJataRCStgnJDGRfSt\n"
                         "-----END RSA PRIVATE KEY-----";

PUBLIC_KEY public_key = RSA_create_public_key(public_key_pem);
PRIVATE_KEY private_key = RSA_create_private_key(private_key_pem);

RSA_ENCRYPT_CONTEXT rsa_encr_ctx = RSA_create_encrypt_ctx(public_key);
RSA_DECRYPT_CONTEXT rsa_decr_ctx = RSA_create_decrypt_ctx(private_key);

SIGN_CONTEXT sign_ctx = RSA_create_sign_ctx(private_key);
VERIFY_CONTEXT verify_ctx = RSA_create_verify_ctx(public_key);

BYTES aes_key = (BYTES) "12345";
ENCRYPT_CONTEXT aes_encr_ctx = AES_create_encrypt_ctx(aes_key, 5, nullptr, 15);
DECRYPT_CONTEXT aes_decr_ctx = AES_create_decrypt_ctx(aes_key, 5, nullptr, 15);


bool base64_test()
{
    cout << "Testing base64 encoding.\n";

    PLAINTEXT text = (PLAINTEXT) "base64 encoding & decoding test.";

    BASE64 encoded_text;
    base64_encode((BYTES)text, strlen(text), &encoded_text);

    cout << "encoded text: " << encoded_text << "\n";

    SIZE outlen;
    BYTES decoded_text;
    base64_decode(encoded_text, &decoded_text, outlen);

    cout << "decoded text: " << decoded_text << "\n";

    bool test_result = not strncmp(text, (PLAINTEXT)decoded_text, outlen) and strlen(text) == outlen;

    free_memory(encoded_text, decoded_text);

    return test_result;
}

bool test_sha()
{
    cout << "Testing sha256 hash.\n";

    PLAINTEXT text = (PLAINTEXT) "sha256 hash test.";
    int *digest = SHA256_digest(text);

    std::string hexdigest = SHA256_hexdigest(digest);

    cout << "Data: " << text << "\n";
    cout << "Calculated sha256 hash: " << hexdigest << "\n";

    return not strcmp("feef4798c260a8c1057b24b1909c08023d23400d57e37f0a759b433c72092320", hexdigest.c_str());
}

bool test_AES()
{
    cout << "Testing AES encryption.\n";

    PLAINTEXT text = (PLAINTEXT) "AES encryption & decryption test.";

    BASE64 ciphertext;
    int result = AES_encrypt(aes_encr_ctx, (BYTES)text, strlen(text), &ciphertext);

    cout << "AES_encrypt: " << result << "\n";
    cout << "encrypted: " << ciphertext << "\n";

    SIZE outlen;
    BYTES decrypted;
    result = AES_decrypt(aes_decr_ctx, ciphertext, &decrypted, outlen);

    cout << "AES_decrypt: " << result << "\n";
    cout << "decrypted: " << (PLAINTEXT)decrypted << "\n";

    bool test_result = not strncmp(text, (PLAINTEXT)decrypted, (SIZE)outlen) and strlen(text) == outlen;

    free_memory(ciphertext, decrypted);

    return test_result;
}

bool test_RSA_sign()
{
    cout << "Testing RSA signing alogorithm.\n";

    PLAINTEXT text = (PLAINTEXT) "RSA signature test.";

    BASE64 signature;
    int result = RSA_sign(private_key, (BYTES)text, strlen(text), &signature);

    cout << "RSA_sign result: " << result << "\n";
    cout << "signature: " << signature << "\n";
    bool authentic;
    result = RSA_verify_signature(public_key, (BYTES)text, strlen(text), signature, authentic);

    cout << "RSA_verify_signature result: " << result << "\n";
    cout << "authentic: " << authentic << "\n";

    bool test_result = authentic;

    cout << "Testing modified text..." << "\n";

    result = RSA_verify_signature(public_key, (BYTES) "modified text", 13, signature, authentic);

    cout << "RSA_verify_signature result: " << result << "\n";
    cout << "authentic: " << authentic << "\n";

    test_result = test_result and not authentic;

    free_memory(signature);

    return test_result;
}

bool test_RSA()
{
    cout << "Testing RSA encryption.\n";

    PLAINTEXT text = (PLAINTEXT) "RSA encryption & decryption test.";

    BASE64 ciphertext;

    int result = RSA_encrypt(public_key, (BYTES)text, strlen(text), &ciphertext);

    cout << "RSA_encrypt result: " << result << "\n";
    cout << "encrypted: " << (PLAINTEXT)ciphertext << "\n";

    size_t outlen;
    BYTES decrypted;

    result = RSA_decrypt(private_key, ciphertext, &decrypted, outlen);

    cout << "RSA_decrypt result: " << result << "\n";
    cout << "decrypted: " << (PLAINTEXT)decrypted << "\n";

    bool test_result = not strncmp(text, (PLAINTEXT)decrypted, outlen) and strlen(text) == outlen;

    free_memory(ciphertext, decrypted);

    return test_result;
}

bool print_result(const char *t, bool r)
{
    printf(t);
    switch (r)
    {
    case 1:
        cout << "SUCCESS!" << '\n';
        break;

    case 0:
        cout << "FAILURE!" << '\n';
        break;
    }

    return r;
}


int main()
{
    cryptography_init();

    bool base64 = print_result("base64 test: ", base64_test());
    cout << '\n';

    bool sha = print_result("SHA256 test: ", test_sha());
    cout << '\n';

    bool AES = print_result("AES test: ", test_AES());
    cout << '\n';

    cout << "encrypt context -> maxlen: " << rsa_encr_ctx->maxlen << ", key length: " << rsa_encr_ctx->bits << " bits.\n";
    cout << "decrypt context -> maxlen: " << rsa_decr_ctx->maxlen << ", key length: " << rsa_decr_ctx->bits << " bits.\n";
    cout << "\n";

    bool sign = print_result("RSA sign test: ", test_RSA_sign());
    printf("\n");

    bool RSA_encrypt = print_result("RSA encryption test: ", test_RSA());
    printf("\n");

    bool tests_passed = print_result("TESTS RESULT: ", base64 and sha and AES and sign and RSA_encrypt);

    AES_free_context(aes_encr_ctx);
    AES_free_context(aes_decr_ctx);

    RSA_free_sign_ctx(sign_ctx);
    RSA_free_verify_ctx(verify_ctx);
    
    RSA_free_context(rsa_encr_ctx);
    RSA_free_context(rsa_decr_ctx);

    RSA_free_key(public_key);
    RSA_free_key(private_key);

    cryptography_cleanup();

    return tests_passed ? EXIT_SUCCESS : EXIT_FAILURE;
}