#include "../../include/v2/sha.h"

std::string sha256(std::string input_string) {
    return sha256(compute_SHA256((char *) input_string.data()));
}

std::string sha256(unsigned char *data, size_t length) {
    return sha256(compute_SHA256(data, length));
}