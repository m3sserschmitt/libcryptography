
#include "../include/cryptography.h"
#include "../include/hash.h"

#include <sstream>
#include <string.h>

Hash::Hash() {
    this->update(this->digest);
}

Hash::Hash(int *d) {
    this->update(d);
}

Hash::Hash(unsigned char *data, size_t length) {
    this->update(data, length);
}

Hash::Hash(std::string s) {
    this->update(s);
}

void Hash::init() {
    for(int i = 0; i < 32; i ++) {
        this->digest[i] = 0;
    }

    memset(this->hexdigest, 0, 65);
}

void Hash::update(int *d) {
    this->init();

    for(int i = 0; i < 32; i ++) {
        this->digest[i] = d[i];
    }

    strcpy(this->hexdigest, sha256(d).data());
}

void Hash::update(std::string s) {
    this->update(compute_SHA256((char *) s.data()));
}

void Hash::update(unsigned char *data, size_t length) {
    this->update(compute_SHA256(data, length));
}

void Hash::update_from_hexdigest(std::string hexdigest) {   
    std::stringstream ss;

    for(int i = 0; i < 63; i += 2) {
        ss << std::hex << hexdigest.substr(i, 2);
        ss >> this->digest[i / 2];
        ss.clear();
    }

    strcpy(this->hexdigest, hexdigest.data());
}

bool Hash::operator>(Hash other_hash) {
    int *other_digest = other_hash.digest;

    for (int i = 0; i < 32; i++) {
        if (this->digest[i] == other_digest[i]) {
            continue;
        }

        return this->digest[i] > other_digest[i];
    }
    return false;
}

bool Hash::operator<(Hash other_hash) {
    int *other_digest = other_hash.digest;

    for (int i = 0; i < 32; i++) {
        if (this->digest[i] == other_digest[i]) {
            continue;
        }

        return this->digest[i] < other_digest[i];
    }
    return false;
}

bool Hash::operator>=(Hash other_hash) {
    return not this->operator<(other_hash);
}

bool Hash::operator<=(Hash other_hash) {
    return not this->operator>(other_hash);
}

bool Hash::operator==(Hash other_hash) {
    int *other_digest = other_hash.digest;

    for (int i = 0; i < 32; i++) {
        if (this->digest[i] != other_digest[i]) {
            return false;
        }
    }
    return true;
}

bool Hash::operator!=(Hash other_hash) {
    return not this->operator==(other_hash);
}