#include <string>

#ifndef HASH_H
#define HASH_H

class Hash {
private:
    void init();
    
public:
    Hash();
    Hash(int *digest);
    Hash(std::string s);
    Hash(unsigned char *data, size_t length);

    void update(int *degest);
    void update(std::string s);
    void update(unsigned char *data, size_t length);
    void update_from_hexdigest(std::string hexdigest);

    bool operator>(Hash);
    bool operator<(Hash);
    bool operator>=(Hash);
    bool operator<=(Hash);
    bool operator==(Hash);
    bool operator!=(Hash);
    
    int digest[32];
    char hexdigest[65];
};

#endif
