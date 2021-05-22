#include "aes.hh"
#include "base64.hh"
#include "rsa.hh"

#include <iostream>
#include <string.h>

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

bool test_base64()
{
    BYTES data = (BYTES) "data to be encoded";
    SIZE datalen = strlen((PLAINTEXT)data);

    BASE64 encoded = 0;
    int enclen = base64_encode(data, datalen, &encoded);

    cout << "encoded size: " << enclen << "\n";
    cout << "encoded data: " << encoded << "\n";

    BYTES decoded = 0;
    int declen = base64_decode(encoded, &decoded);

    bool result = (int)datalen == declen and not strcmp((PLAINTEXT)data, (PLAINTEXT)decoded);

    free(encoded);
    free(decoded);

    return result;
}

bool test_AES()
{
    AES_CRYPTO ctx = AES_CRYPTO_new();

    BYTES data = (BYTES) "this is text to be encrypted";
    SIZE datalen = strlen((PLAINTEXT)data);

    BYTES key = (BYTES) "9873876HDiid#*&@!";
    SIZE keylen = strlen((PLAINTEXT)key);

    cout << "AES init: " << AES_init(key, keylen, 0, 15, ctx) << "\n";

    BYTES encrypted = 0;
    int enclen = AES_encrypt(ctx, data, datalen, &encrypted);

    cout << "encrypted size: " << enclen << "\n";

    BYTES decrypted = 0;
    int decrlen = AES_decrypt(ctx, encrypted, enclen, &decrypted);
    cout << "decrypted size: " << decrlen << "\n";

    cout << decrypted << "\n";

    bool result = (int)datalen == decrlen and not strcmp((PLAINTEXT)data, (PLAINTEXT)decrypted);

    free(encrypted);
    free(decrypted);

    return result;
}

bool test_RSA()
{
    RSA_CRYPTO ctx = RSA_CRYPTO_new();

    cout << "pubkey init: " << RSA_init_key(public_key_pem, 0, 0, PUBLIC_KEY, ctx) << "\n";
    cout << "privkey init: " << RSA_init_key(private_key_pem, 0, 0, PRIVATE_KEY, ctx) << "\n";

    cout << "sign ctx init: " << RSA_init_ctx(ctx, SIGN) << "\n";
    cout << "verify init ctx: " << RSA_init_ctx(ctx, VERIFY) << "\n";

    cout << "encrypt ctx init: " << RSA_init_ctx(ctx, ENCRYPT) << "\n";
    cout << "decrypt ctx init: " << RSA_init_ctx(ctx, DECRYPT) << "\n";

    BYTES data = (BYTES) "text to be signed";
    SIZE datalen = strlen((PLAINTEXT)data);

    BYTES sign = 0;
    int signlen = RSA_sign(ctx, data, datalen, &sign);
    cout << "signlen: " << signlen << "\n";

    bool auth;

    cout << "verify: " << RSA_verify(ctx, sign, signlen, data, datalen, auth) << "\n";
    cout << "authentic: " << auth << "\n";

    bool auth2;
    cout << "verify changed data: " << RSA_verify(ctx, sign, signlen, (BYTES) "changed data", 12, auth2) << "\n";
    cout << "authentic (changed data): " << auth2 << "\n";

    free(sign);

    BYTES encr = 0;
    int encrlen = RSA_encrypt(ctx, data, datalen, &encr);
    
    
    
    cout << "encrlen: " << encrlen << "\n";

    BYTES decr = 0;
    int decrlen = RSA_decrypt(ctx, encr, encrlen, &decr);

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