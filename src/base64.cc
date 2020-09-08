
/*
 * Base64 encoding / decoding implementation.
*/

#include "../include/cryptography.h"

#include <openssl/pem.h>
#include <vector>


/*
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
*/
void Cryptography::base64_encode(unsigned char *in, size_t inlen, char *out) {
    size_t encoded_len = get_encode_length(inlen) + 1;
    char *out_buffer = (char *) malloc(encoded_len);
    char *addr = out_buffer;

    memset(out_buffer, 0, encoded_len);

    int val=0, valb=-6;
    for (size_t i = 0; i < inlen; i ++) {
        val = (val<<8) + in[i];
        valb += 8;
        while (valb>=0) {
            *addr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val>>valb)&0x3F];
            addr ++;
            valb-=6;
        }
    }

    if(valb > -6) {
        *addr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val<<8)>>(valb+8))&0x3F];
        addr ++;
    }

    while(strlen(out_buffer) % 4) {
        *addr = '=';
        addr ++;
    }
    
    strcpy(out, out_buffer);
    free(out_buffer);
}
/*
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
*/
void Cryptography::base64_decode(char *in, unsigned char *out, size_t &outlen) {
    outlen = 0;
    size_t required_memory = get_decode_length(strlen(in)) + 1;

    unsigned char *out_buffer = (unsigned char *) malloc(required_memory);
    memset(out_buffer, 0, required_memory);

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    unsigned char *addr = out_buffer;

    for (char *c = in; *c; c++) {
        if (T[*c] == -1) break;
        val = (val<<6) + T[*c];
        valb += 6;
        if (valb>=0) {
            *addr = (char) (val>>valb)&0xFF;
            addr ++;
            valb-=8;
            outlen ++;
        }
    }

    memcpy(out, out_buffer, outlen);
    free(out_buffer);
}

size_t Cryptography::get_encode_length(size_t buffer_length)
{
	return (buffer_length + 2) * 4 / 3;
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
	return (len * 3) / 4 - padding;
}