

/*
 * Secure Hash Algorithm 2 (SHA256) implementation with Openssl cryptographic
 * library.
*/

#include "../include/cryptography.h"

#include <sstream>
#include <iomanip>


int* Cryptography::compute_SHA256(unsigned char *input_string, size_t length) {
    unsigned char *output_buffer = (unsigned char *) malloc(32);
    memset(output_buffer, 0, 32);

    SHA256(input_string, length, output_buffer);

    return (int *) output_buffer;
}

int *Cryptography::compute_SHA256(char *input_string) {
    return compute_SHA256((unsigned char *) input_string, strlen(input_string));
}

std::string Cryptography::sha256(int *digest) {
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');

    for (int i = 0; i < 32; i++) {
        shastr << std::setw(2) << digest[i];
    }

    return shastr.str();
}

std::string Cryptography::sha256(std::string input_string) {
    return sha256(compute_SHA256((char *) input_string.data()));
}

std::string Cryptography::sha256(unsigned char *data, size_t length) {
    return sha256(compute_SHA256(data, length));
}
