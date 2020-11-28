#include "typedefs.h"
#include "sha.h"

#include <string>

#ifndef HASH_H
#define HASH_H

class Hash
{
    int *digest;
    char *hexdigest;

    void init();

public:
    Hash();
    Hash(const Hash &);
    Hash(DIGEST digest);
    Hash(PLAINTEXT in);
    Hash(BYTES in, SIZE inlen);

    void update(DIGEST degest);
    void update(PLAINTEXT in);
    void update(BYTES in, SIZE inlen);
    void haxdigest_update(std::string hexdigest);

    int operator[](SIZE i);
    Hash &operator=(Hash &hash);

    bool operator>(Hash);
    bool operator<(Hash);
    bool operator>=(Hash);
    bool operator<=(Hash);
    bool operator==(Hash);
    bool operator!=(Hash);

    friend std::ostream &operator<<(std::ostream &out, Hash &hash);
};

#endif
