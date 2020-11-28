#include "crypto/v3/aes.h"
#include "crypto/v2/base64.h"

size_t AES_get_encoded_size(SIZE inlen) {
	return base64_get_encoded_length(AES_get_encrypted_size(inlen));
}

size_t AES_get_decoded_size(SIZE inlen) {
	return AES_get_decrypted_size(base64_get_decoded_length(inlen));
}

int AES_encrypt(ENCRYPT_CONTEXT encr, BYTES in, SIZE inlen, BASE64 out)
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

int AES_decrypt(DECRYPT_CONTEXT decr, BASE64 in, BYTES out, SIZE &outlen)
{
	size_t decoded_length;
	unsigned char *decoded;

	base64_decode(in, &decoded, decoded_length);

	int result = AES_decrypt(decr, decoded, decoded_length, out, outlen);
	free(decoded);

	return result;
}