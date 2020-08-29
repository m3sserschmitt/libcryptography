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
 * Base64 encoding / decoding implementation.
*/

#include "../include/cryptography.h"

#include <openssl/pem.h>
#include <string.h>
#include <vector>

std::string Cryptography::base64_encode(unsigned char *in, size_t length) {
    std::string out;

    int val=0, valb=-6;
    for (size_t i = 0; i < length; i ++) {
        val = (val<<8) + in[i];
        valb += 8;
        while (valb>=0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val>>valb)&0x3F]);
            valb-=6;
        }
    }

    if (valb>-6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    
    return out;
}

unsigned char *Cryptography::base64_decode(std::string in, size_t &outlen) {
    outlen = 0;
    size_t required_memory = get_decode_length((char *) in.data());
    unsigned char *out = (unsigned char *) malloc(required_memory);
    memset(out, 0, required_memory);

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    unsigned char *addr = out;
    for (char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            *addr = (char) (val>>valb)&0xFF;
            addr ++;
            valb-=8;
            outlen ++;
        }
    }

    return out;
}

size_t Cryptography::get_encode_length(size_t buffer_length)
{
	return (buffer_length + 2) * 4 / 3 + 1;
}

size_t Cryptography::get_decode_length(size_t encoded_length) {
    return (encoded_length * 3) / 4;
}

size_t Cryptography::get_decode_length(char *b64input)
{
	size_t len = strlen(b64input), padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len - 1] == '=') //last char is =
		padding = 1;
	return (len * 3) / 4 - padding + 1;
}