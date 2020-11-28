
#include "crypto/v1/hash.h"
#include "crypto/v1/mem.h"

#include <sstream>
#include <string.h>

Hash::Hash()
{
    allocate_memory(&this->digest, 32);
    allocate_memory(&this->hexdigest, 65);
}

Hash::Hash(const Hash &hash)
{
    allocate_memory(&this->digest, 32);
    allocate_memory(&this->hexdigest, 65);

    strcpy(this->hexdigest, hash.hexdigest);

    for (int i = 0; i < 64; i++)
    {
        this->digest[i] = hash.digest[i];
    }
}

Hash::Hash(DIGEST digest)
{
    allocate_memory(&this->digest, 32);
    allocate_memory(&this->hexdigest, 65);

    this->update(digest);
}

Hash::Hash(BYTES in, SIZE inlen)
{
    allocate_memory(&this->digest, 32);
    allocate_memory(&this->hexdigest, 65);

    this->update(in, inlen);
}

void Hash::update(DIGEST digest)
{
    for (int i = 0; i < 32; i++)
    {
        this->digest[i] = digest[i];
    }

    strcpy(this->hexdigest, SHA256_hexdigest(digest).data());
}

void Hash::update(BYTES in, SIZE inlen)
{
    this->update(SHA256_digest(in, inlen));
}

void Hash::update(PLAINTEXT in)
{
    this->update(SHA256_digest(in));
}

void Hash::haxdigest_update(std::string hexdigest)
{
    std::stringstream ss;

    for (int i = 0; i < 63; i += 2)
    {
        ss << std::hex << hexdigest.substr(i, 2);
        ss >> this->digest[i / 2];
        ss.clear();
    }

    strcpy(this->hexdigest, hexdigest.data());
}

int Hash::operator[](SIZE i)
{
    return this->digest[i];
}

Hash &Hash::operator=(Hash &hash)
{
    if (this != &hash)
    {
        strcpy(this->hexdigest, hash.hexdigest);

        for (int i = 0; i < 64; i++)
        {
            this->digest[i] = hash.digest[i];
        }
    }

    return *this;
}

bool Hash::operator>(Hash hash)
{
    DIGEST hash_digest = hash.digest;

    for (int i = 0; i < 32; i++)
    {
        if (this->digest[i] == hash_digest[i])
        {
            continue;
        }

        return this->digest[i] > hash_digest[i];
    }
    return false;
}

bool Hash::operator<(Hash hash)
{
    DIGEST hash_digest = hash.digest;

    for (int i = 0; i < 32; i++)
    {
        if (this->digest[i] == hash_digest[i])
        {
            continue;
        }

        return this->digest[i] < hash_digest[i];
    }
    return false;
}

bool Hash::operator>=(Hash hash)
{
    return not this->operator<(hash);
}

bool Hash::operator<=(Hash hash)
{
    return not this->operator>(hash);
}

bool Hash::operator==(Hash hash)
{
    DIGEST hash_digest = hash.digest;

    for (int i = 0; i < 32; i++)
    {
        if (this->digest[i] != hash_digest[i])
        {
            return false;
        }
    }
    return true;
}

bool Hash::operator!=(Hash hash)
{
    return not this->operator==(hash);
}

std::ostream &operator<<(std::ostream &out, Hash &hash)
{
    out << hash.hexdigest;
    return out;
}
