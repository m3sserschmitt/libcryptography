#include "../../include/v2/aes.h"
#include "../../include/v1/base64.h"

size_t get_AES_encrypted_encoded_size(size_t plaintext_size) {
	return get_encoded_length(get_AES_encrypted_size(plaintext_size));
}

size_t get_AES_decrypted_decoded_size(size_t ciphercode_size) {
	return get_AES_decrypted_size(get_decoded_length(ciphercode_size));
}

int AES_encrypt(EVP_CIPHER_CTX *encrypt_ctx, unsigned char *in, size_t inlen, char *out)
{
	size_t outlen;
	int result = AES_encrypt(encrypt_ctx, in, inlen, (unsigned char *) out, outlen);

	if (result < 0)
	{
		return result;
	}
	
	base64_encode((unsigned char *) out, outlen, out);
    // strcpy(out, base64_encode((unsigned char *) out, outlen).data());
    
	return result;
}

int AES_decrypt(EVP_CIPHER_CTX *decrypt_ctx, char *in, unsigned char *out, size_t &outlen)
{
	size_t decoded_length;
	unsigned char *decoded = (unsigned char *) malloc(get_decoded_length(in));

	base64_decode(in, decoded, decoded_length);
	// unsigned char *decoded = base64_decode(in, decoded_length);

	int result = AES_decrypt(decrypt_ctx, decoded, decoded_length, out, outlen);
	free(decoded);

	return result;
}