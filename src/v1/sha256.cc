#include "../../include/v1/sha.h"

#include <sstream>
#include <iomanip>
#include <string.h>


int* compute_SHA256(unsigned char *input_string, size_t length) {
    unsigned char *output_buffer = (unsigned char *) malloc(32);
    memset(output_buffer, 0, 32);

    SHA256(input_string, length, output_buffer);

    return (int *) output_buffer;
}

int *compute_SHA256(char *input_string) {
    return compute_SHA256((unsigned char *) input_string, strlen(input_string));
}

std::string sha256(int *digest) {
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');

    for (int i = 0; i < 32; i++) {
        shastr << std::setw(2) << digest[i];
    }

    return shastr.str();
}