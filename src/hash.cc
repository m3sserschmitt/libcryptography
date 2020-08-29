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

#include "../include/cryptography.h"

#include <string>
#include <string.h>
#include <sstream>

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

    strcpy(this->hexdigest, Cryptography::sha256(d).data());
}

void Hash::update(std::string s) {
    this->update(Cryptography::compute_SHA256(s));
}

void Hash::update(unsigned char *data, size_t length) {
    this->update(Cryptography::compute_SHA256(data, length));
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