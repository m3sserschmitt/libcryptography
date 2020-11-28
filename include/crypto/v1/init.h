/**
 * Initialize cryptography algorithms. It should be called before any other 
 * cryptographic operation.
*/
void cryptography_init();

/**
 * Cleanup memory. It should be called when no other cryptographic operation
 * it's required.
*/
void cryptography_cleanup();