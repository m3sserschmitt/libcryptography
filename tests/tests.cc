#include "../include/cryptography.h"

#include <string.h>

std::string public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojYb5h0vm9YEK5sDO6fJ\n"
                             "CH0qFik8p7yB2XTqA0rj1v52+trmMWxI5X3JmFUCMr+vx+kiwBTcud4AwrvkcV3o\n"
                             "4Vi4zgr/UbV04D1VddCGxrTPkelKqKbQCYPIVtzJ5ZJtPBPaCgoBHgy9K/wYIfnS\n"
                             "77ybULYJFFDKEgcI6sjPlYg/PTYQKzsqRRYE2Ec/ctALOWL56ZA31pkdih9xhuID\n"
                             "gon4el4s31oaAoUHaF7eUR8iWIjvFMsdzm8GSYvZJTkQzMy9YiSrQUXhNXzOiV1P\n"
                             "A9cp8YQ2KaB1f5Tj648c9TaChdwzA+5MZPUmeQve+stwm8h+CreIMbiRAQ2Mf0HU\n"
                             "OQIDAQAB\n"
                             "-----END PUBLIC KEY-----";

std::string private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
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

bool test_AES()
{
    PLAINTEXT text = (PLAINTEXT)"AES encryption & decryption test.";
    PLAINTEXT aes_key = (PLAINTEXT)"12345";

    ENCRYPT_CTX encr;
    DECRYPT_CTX decr;
    int result = AES_init((BYTES)aes_key, strlen(aes_key), nullptr, 15, &encr, &decr);

    printf("AES_init: %i\n", result);

    BASE64 ciphertext;
    result = AES_encrypt(encr, (BYTES)text, strlen(text), &ciphertext);

    printf("AES_encrypt: %i\n", result);
    printf("encrypted: %s\n", ciphertext);

    SIZE outlen;
    BYTES decrypted;
    result = AES_decrypt(decr, ciphertext, &decrypted, outlen);

    printf("AES_decrypt: %i\n", result);
    printf("decrypted: %s\n", (PLAINTEXT)decrypted);

    bool test_result = not strncmp(text, (PLAINTEXT)decrypted, (SIZE)outlen) and strlen(text) == outlen;
    
    free(ciphertext);
    free(decrypted);

    AES_free_context(encr);
    AES_free_context(decr);

    return test_result;
}

bool test_RSA()
{
    PLAINTEXT text = (PLAINTEXT)"RSA encryption & decryption test.";

    PUBLIC_KEY public_key = create_public_RSA(public_key_pem);

    BASE64 ciphertext;
    int result = RSA_encrypt((BYTES)text, strlen(text), &ciphertext, public_key);
    
    printf("RSA_encrypt result: %i\n", result);
    printf("encrypted: %s\n", (PLAINTEXT)ciphertext);

    PRIVATE_KEY private_key = create_private_RSA(private_key_pem);

    size_t outlen;
    BYTES decrypted;
    result = RSA_decrypt(ciphertext, &decrypted, outlen, private_key);

    printf("RSA_decrypt result: %i\n", result);
    printf("decrypted: %s\n", (PLAINTEXT)decrypted);

    bool test_result = not strncmp(text, (PLAINTEXT)decrypted, outlen) and strlen(text) == outlen;

    free(ciphertext);
    free(decrypted);

    RSA_free_key(public_key);
    RSA_free_key(private_key);

    return test_result;
}

bool test_RSA_sign()
{
    PLAINTEXT text = (PLAINTEXT)"RSA signature test.";
    PRIVATE_KEY private_key = create_private_RSA(private_key_pem);
    PUBLIC_KEY public_key = create_public_RSA(public_key_pem);

    BASE64 signature;
    int result = RSA_sign(private_key, (BYTES)text, strlen(text), &signature);

    printf("RSA_sign result: %i\n", result);
    printf("signature: %s\n", signature);

    bool authentic;
    result = RSA_verify_signature(public_key, (BYTES)text, strlen(text), signature, authentic);

    printf("RSA_verify_signature result: %i\n", result);
    printf("authentic: %i\n", authentic);

    bool test_result = authentic;

    printf("Testing modified text...\n");

    result = RSA_verify_signature(public_key, (BYTES)"modified text", 13, signature, authentic);
    
    printf("RSA_verify_signature result: %i\n", result);
    printf("authentic: %i\n", authentic);

    test_result = test_result and not authentic;

    free(signature);
    RSA_free_key(private_key);
    RSA_free_key(public_key);

    return test_result;
}

bool base64_encode_test()
{
    PLAINTEXT text = (PLAINTEXT)"base64 encoding & decoding test.";

    BASE64 encoded_text;
    base64_encode((BYTES)text, strlen(text), &encoded_text);

    printf("encoded text: %s\n", encoded_text);

    SIZE outlen;
    BYTES decoded_text;
    base64_decode(encoded_text, &decoded_text, outlen);

    printf("decoded text: %s\n", decoded_text);

    bool test_result = not strncmp(text, (PLAINTEXT)decoded_text, outlen) and strlen(text) == outlen;

    free(encoded_text);
    free(decoded_text);

    return test_result;
}


bool print_result(const char *t, bool r) {
    printf(t);
    switch (r)
    {
    case 1:
        printf("SUCCESS!\n");
        break;
    
    case 0:
        printf("FAILURE!\n");
        break;
    }

    return r;
}

int main()
{
    cryptography_init();

    bool base64 = print_result("base64 test: ", base64_encode_test());
    printf("\n");

    bool AES = print_result("AES test: ", test_AES());
    printf("\n");

    bool sign = print_result("RSA sign test: ", test_RSA_sign());
    printf("\n");

    bool RSA_encrypt = print_result("RSA encryption test: ", test_RSA());
    printf("\n");
    
    bool tests_passed = print_result("TESTS RESULT: ", base64 and AES and sign and RSA_encrypt);

    cryptography_cleanup();

    return tests_passed ? EXIT_SUCCESS : EXIT_FAILURE;
}