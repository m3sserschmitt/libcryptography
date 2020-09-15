#include "../../include/v3/aes.h"
#include "../../include/v2/base64.h"

size_t get_AES_encoded_size(SIZE inlen) {
	return get_encoded_length(get_AES_encrypted_size(inlen));
}

size_t get_AES_decoded_size(SIZE inlen) {
	return get_AES_decrypted_size(get_decoded_length(inlen));
}

int AES_encrypt(ENCRYPT_CTX encr, BYTES in, SIZE inlen, BASE64 out)
{
	size_t outlen;
	int result = AES_encrypt(encr, in, inlen, (unsigned char *) out, outlen);

	if (result < 0)
	{
		return result;
	}
	
	base64_encode((unsigned char *) out, outlen, out);
    
	return result;
}

int AES_decrypt(DECRYPT_CTX decr, BASE64 in, BYTES out, SIZE &outlen)
{
	size_t decoded_length;
	unsigned char *decoded;

	base64_decode(in, &decoded, decoded_length);

	int result = AES_decrypt(decr, decoded, decoded_length, out, outlen);
	free(decoded);

	return result;
}