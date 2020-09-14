#include "../../include/v2/sha.h"

std::string sha256(std::string in) {
    return sha256(compute_SHA256((char *) in.data()));
}

std::string sha256(BYTES in, SIZE inlen) {
    return sha256(compute_SHA256(in, inlen));
}