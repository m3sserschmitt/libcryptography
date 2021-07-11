#include "cryptex.hh"
#include "util/util.hh"
#include "util/help.hh"

#include <iostream>
#include <unistd.h>

#include <string.h>

using namespace std;

static bool silent = false;

int main(int argc, char **argv)
{
    if(cmd_option_exists(argv, argc, "-version"))
    {
        cout << "cryptutil version 5.0.0\n";
        return EXIT_SUCCESS;
    }

    if (cmd_option_exists(argv, argc, "-help"))
    {
        cout << help << "\n";

        return EXIT_SUCCESS;
    }

    BYTES in;
    SIZE inlen;
    CRYPTO ctx = new _CRYPTO;

    ctx->aes = AES_CRYPTO_new();
    ctx->rsa = RSA_CRYPTO_new();

    silent = cmd_option_exists(argv, argc, "-silent");

    if (not cmd_option_exists(argv, argc, "-in"))
    {
        if (not read_stdin(&in, inlen, ctx))
        {
            silent or cout << "[-] Cannot read stdin.\n";

            return EXIT_FAILURE;
        }
    }
    else
    {
        in = read_file(argv, argc, inlen);

        if (not in)
        {
            silent or cout << "[-] Error: cannot read file.\n";

            return EXIT_FAILURE;
        }

        if (not read_password(argv, argc, ctx))
        {
            silent or cout << "[-] ERROR: Cannot read password / key.\n";

            return EXIT_FAILURE;
        }
    }

    BYTES out = 0;
    

    // cryptography_init();
    int outlen = cryptography(ctx, in, inlen, argv, argc, &out);
    // cryptography_cleanup();
    bool ok = outlen >= 0;
    silent or cout << "[+] Input: " << inlen << " bytes.\n"
                   << "[+] Result: " << ok;

    if (not ok)
    {
        silent or cout << " (FAILURE).\n";

        return EXIT_FAILURE;
    }

    silent or cout << " (SUCCESS).\n"
                   << "[+] Out: " << outlen << " bytes.\n";

    if (not cmd_option_exists(argv, argc, "-out"))
    {
        write(1, out, outlen);
    }
    else if (not write_file(out, outlen, argv, argc))
    {
        silent or cout << "[-] Error: cannot write result into file.\n";

        return EXIT_FAILURE;
    }

    silent or cout << "[+] Done.\n";

    return EXIT_SUCCESS;
}
