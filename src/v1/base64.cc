
/*
 * Base64 encoding / decoding implementation.
*/

#include "../../include/v1/base64.h"

#include <stdlib.h>
#include <vector>
#include <string.h>

size_t get_encoded_length(SIZE inlen)
{
	return (inlen + 2) * 4 / 3;
}

size_t get_decoded_length(SIZE inlen) {
    return (inlen * 3) / 4;
}

size_t get_decoded_length(BASE64 in)
{
	size_t len = strlen(in), padding = 0;

	if (in[len - 1] == '=' && in[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (in[len - 1] == '=') //last char is =
		padding = 1;
	return (len * 3) / 4 - padding;
}

void base64_encode(BYTES in, SIZE inlen, BASE64 out) {
    size_t encoded_len = get_encoded_length(inlen) + 1;
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

void base64_decode(BASE64 in, BYTES out, SIZE &outlen) {
    outlen = 0;
    size_t required_memory = get_decoded_length(strlen(in)) + 1;

    unsigned char *out_buffer = (unsigned char *) malloc(required_memory);
    memset(out_buffer, 0, required_memory);

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    unsigned char *addr = out_buffer;

    for (char *c = in; c; c++) {
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
