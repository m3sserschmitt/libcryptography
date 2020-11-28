/**
 * \file sha.h
 * \brief SHA256 operations.
*/

#include <string>
#include "typedefs.h"


/**
 * Returns an array containing message digest.
 * 
 * @param in data to compute SHA256;
 * @param inlen length of input data;
 */
DIGEST SHA256_digest(BYTES in, SIZE inlen);

/**
 * Compute SHA256. Returns an array containing message digest.
 * 
 * @param in data to compute SHA256;
 */
DIGEST SHA256_digest(PLAINTEXT in);

/**
 * Creates a 64 bytes SHA256 hexdigest from a digest.
 * 
 * @param digest digest to convert into hexdigest; 
 */
std::string SHA256_hexdigest(DIGEST digest);

/**
 * Creates SHA256 hexdigest of provided data.
 * 
 * @param in data to compute SHA256; 
 * @param inlen data length;
 */
std::string SHA256_hexdigest(BYTES in, SIZE inlen);

/**
 * Creates SHA256 hexdigest of input data.
 * 
 * @param in data to compute SHA256; 
 */
std::string SHA256_hexdigest(std::string in);