/*
MIT License

Copyright (c) 2020 Romulus-Emanuel Ruja (romulus-emanuel.ruja@tutanota.com).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
 * Secure Hash Algorithm 2 (SHA256) implementation with Openssl cryptographic
 * library.
*/

#include "../include/cryptography.h"

#include <openssl/sha.h>
#include <string.h>
#include <sstream>
#include <iomanip>

int* Cryptography::compute_SHA256(unsigned char *input_string, size_t length) {
    int *result = new int[32];
    unsigned char *output_buffer = new unsigned char[32];

    memset(output_buffer, 0, 32);

    SHA256(input_string, length, output_buffer);

    for (int i = 0; i < 32; i++) {
        result[i] = (int) output_buffer[i];
    }

    return result;
}

int *Cryptography::compute_SHA256(std::string input_string) {
    return compute_SHA256((unsigned char *) input_string.c_str(), input_string.size());
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
    return sha256(compute_SHA256(input_string));
}

std::string Cryptography::sha256(unsigned char *data, size_t length) {
    return sha256(compute_SHA256(data, length));
}
