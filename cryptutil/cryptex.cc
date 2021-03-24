#include "cryptex.hh"
#include "util/log.hh"

#include <iostream>
#include <string>
#include <fstream>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

using namespace std;

static char getch()
{
    char buf = 0;
    struct termios old = {0};
    if (tcgetattr(0, &old) < 0)
        perror("tcsetattr()");
    old.c_lflag &= ~ICANON;
    old.c_lflag &= ~ECHO;
    old.c_cc[VMIN] = 1;
    old.c_cc[VTIME] = 0;
    if (tcsetattr(0, TCSANOW, &old) < 0)
        perror("tcsetattr ICANON");
    if (read(0, &buf, 1) < 0)
        perror("read()");
    old.c_lflag |= ICANON;
    old.c_lflag |= ECHO;
    if (tcsetattr(0, TCSADRAIN, &old) < 0)
        perror("tcsetattr ~ICANON");
    return (buf);
}

static PLAINTEXT keyboard_read_key(SIZE &inlen)
{
    char c = 0;
    char *password = (char *)malloc(1024);
    char *ptr = password;

    memset(password, 0, 1024);

    cout << "enter password:\n";

    do
    {
        c = getch();

        if (c == '\b' and ptr != password)
        {
            *ptr = 0;
            ptr--;
            continue;
        }

        *ptr = c;
        ptr++;

    } while (c != '\n');

    ptr--;
    *ptr = 0;

    inlen = strlen(password);
    return password;
}

bool read_stdin(BYTES *in, SIZE &inlen, CRYPTO crypto)
{
    *in = (BYTES)calloc(4086, sizeof(char));
    
    ssize_t bytes_read = read(0, *in, 4086);
    
    if(bytes_read <=0)
    {
        return NULL;
    }

    size_t keylen = strlen((PLAINTEXT)*in);

    // ctx->aes_encr = AES_create_encrypt_ctx(in, keylen, NULL, 15);
    // ctx->aes_decr = AES_create_decrypt_ctx(in, keylen, NULL, 15);
    bool result = AES_init(*in, keylen, 0, 15, crypto->aes) == 0;
    inlen = bytes_read - keylen - 1;
    memcpy(*in, *in + keylen + 1, inlen);

    return result;
}

bool read_password(PLAINTEXT *argv, SIZE argc, CRYPTO crypto)
{
    SIZE keylen;

    if (cmd_one_exists(argv, argc, "-encrypt", "-decrypt"))
    {
        BYTES key;

        key = (BYTES)keyboard_read_key(keylen);

        if (!key)
        {
            return 0;
        }

        return AES_init(key, keylen, 0, 15, crypto->aes) == 0;
    }
    else
    {
        PLAINTEXT keyfile = get_cmd_option(argv, argc, "-key");

        if (not keyfile)
        {
            return 0;
        }

        PLAINTEXT command[] = {"-in", keyfile};
        PLAINTEXT key = (PLAINTEXT)read_file(command, 2, keylen);

        if (cmd_option_exists(argv, argc, "-sign"))
        {
            return not RSA_init_key(key, 0, 0, PRIVATE_KEY, crypto->rsa) and not RSA_init_ctx(crypto->rsa, SIGN);
        }
        else if (cmd_option_exists(argv, argc, "-verify"))
        {
            return not RSA_init_key(key, 0, 0, PUBLIC_KEY, crypto->rsa) and not RSA_init_ctx(crypto->rsa, VERIFY);
        }
        else if (cmd_option_exists(argv, argc, "-rsa_encrypt"))
        {
            return not RSA_init_key(key, 0, 0, PUBLIC_KEY, crypto->rsa) and not RSA_init_ctx(crypto->rsa, ENCRYPT);
        }
        else if (cmd_option_exists(argv, argc, "-rsa_decrypt"))
        {
            return not RSA_init_key(key, 0, 0, PRIVATE_KEY, crypto->rsa) and not RSA_init_ctx(crypto->rsa, DECRYPT);
        }
    }

    return 0;
}

bool write_file(BYTES data, SIZE datalen, PLAINTEXT *argv, SIZE argc)
{
    std::fstream file;

    bool encoded = cmd_option_exists(argv, argc, "-encode");
    char *out = get_cmd_option(argv, argc, "-out");

    if (not out)
    {
        log(argv, argc, "[-] ERROR: write_file: No output file.");
        return false;
    }

    if (encoded)
    {
        file.open(out, std::ios::out);
    }
    else
    {
        file.open(out, std::ios::out | std::ios::binary);
    }

    if (not file.is_open())
    {
        log(argv, argc, "[-] ERROR: write_file: Cannot open output file.");
        return false;
    }

    file.write((const char *)data, datalen);
    file.close();

    return true;
}

BYTES read_file(PLAINTEXT *argv, SIZE argc, SIZE &file_size)
{
    file_size = 0;
    std::fstream file;

    char *in = get_cmd_option(argv, argc, "-in");

    if (not in)
    {
        log(argv, argc, "[-] ERROR: read_file: No input file.");
        return nullptr;
    }

    bool binary = cmd_option_exists(argv, argc, "-binary");

    if (binary)
    {
        file.open(in, std::ios::in | std::ios::binary);
    }
    else
    {
        file.open(in, std::ios::in);
    }

    if (not file.is_open())
    {
        log(argv, argc, "[-] ERROR: read_file: Cannot open input file.");
        return nullptr;
    }

    file.seekg(0, std::ios::end);
    file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    unsigned char *data_buffer = (unsigned char *)malloc(file_size + 1);

    if (not data_buffer)
    {
        log(argv, argc, "[-] ERROR: read_file: memory allocation error: malloc.");
        return nullptr;
    }

    memset(data_buffer, 0, file_size + 1);

    file.read((char *)data_buffer, file_size);
    file.close();

    return data_buffer;
}

int cryptography(CRYPTO ctx, BYTES in, SIZE inlen, PLAINTEXT *argv, SIZE argc, BYTES *out)
{
    int outlen = 0;

    if (not inlen)
    {
        log(argv, argc, "[-] WARNING: cryptography: input buffer empty.");
        return outlen;
    }

    BYTES dec = 0;

    if (cmd_option_exists(argv, argc, "-decode"))
    {
        outlen = base64_decode((BASE64)in, &dec);
        in = dec;
        inlen = outlen;
    }

    BYTES encr = 0;

    if (cmd_option_exists(argv, argc, "-encrypt"))
    {
        outlen = AES_encrypt(ctx->aes, in, inlen, &encr);
    }
    else if (cmd_option_exists(argv, argc, "-decrypt"))
    {
        outlen = AES_decrypt(ctx->aes, in, inlen, &encr);
    }
    else if (cmd_option_exists(argv, argc, "-rsa_encrypt"))
    {
        outlen = RSA_encrypt(ctx->rsa, in, inlen, &encr);
    }
    else if (cmd_option_exists(argv, argc, "-rsa_decrypt"))
    {
        outlen = RSA_decrypt(ctx->rsa, in, inlen, &encr);
    }
    else if (cmd_option_exists(argv, argc, "-sign"))
    {
        outlen = RSA_sign(ctx->rsa, in, inlen, &encr);
    }
    else if (cmd_option_exists(argv, argc, "-verify"))
    {
        bool auth;
        PLAINTEXT signfile = get_cmd_option(argv, argc, "-signature");

        if (not signfile)
        {
            cout << "[-] Error: Signature is missing.\n";
            return outlen;
        }

        PLAINTEXT command[] = {"-in", signfile};
        SIZE signlen;
        BYTES sign = read_file(command, 2, signlen);

        if (not sign)
        {
            cout << "[-] Error: Cannot read signature file.\n";
            return outlen;
        }

        outlen = RSA_verify(ctx->rsa, sign, signlen, in, inlen, auth);
        outlen = 0;

        cout << "[+] Valid: " << auth << ".\n";

        free(sign);
    }

    if (outlen and cmd_option_exists(argv, argc, "-encode"))
    {
        outlen = base64_encode(encr, outlen, (BASE64 *)out);
        free(encr);

        return outlen;
    }

    *out = encr;

    return outlen;
}
