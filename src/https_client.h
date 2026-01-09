/*
 * HTTPS client header file
 */

#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include <stddef.h>

/*
 * Initialize HTTPS client with certificate configuration
 * base_url: Base URL of signing service
 * client_cert_path: Path to client certificate file (PEM format)
 * client_key_path: Path to client private key file (PEM format)
 * environment: "test" or "prod" (default: "test")
 * Returns: 0 on success, -1 on error
 */
int https_client_init(const char *base_url, const char *client_cert_path,
                      const char *client_key_path, const char *environment);

/*
 * Cleanup HTTPS client resources
 */
void https_client_cleanup(void);

/*
 * Request signature from HTTPS signing service
 * hash: binary SHA-256 hash data (32 bytes)
 * hash_len: length of hash data (must be 32)
 * algorithm: algorithm identifier string (e.g., "rsa-sign-pkcs1-2048-sha256")
 * signature: output buffer for signature (caller must free)
 * signature_len: output length of signature
 * Returns: 0 on success, -1 on error
 */
int https_request_signature(const unsigned char *hash, size_t hash_len,
                            const char *algorithm,
                            unsigned char **signature, size_t *signature_len);

/*
 * Test HTTPS service connectivity
 * Returns: 0 on success (service is reachable), -1 on error
 */
int https_test_connectivity(void);

/*
 * Get public key from HTTPS signing service for a specific algorithm
 * algorithm: algorithm identifier string (e.g., "rsa-sign-pkcs1-2048-sha256")
 * public_key_pem: output buffer for public key in PEM format (caller must free)
 * Returns: 0 on success, -1 on error
 */
int https_get_public_key(const char *algorithm, char **public_key_pem);

/*
 * Verify signature using public key
 * hash: binary SHA-256 hash data (32 bytes)
 * hash_len: length of hash data (must be 32)
 * signature: signature data
 * signature_len: length of signature
 * public_key_pem: public key in PEM format
 * algorithm: algorithm identifier string (e.g., "rsa-sign-pkcs1-2048-sha256")
 * Returns: 0 on success (signature valid), -1 on error (signature invalid)
 */
int https_verify_signature(const unsigned char *hash, size_t hash_len,
                          const unsigned char *signature, size_t signature_len,
                          const char *public_key_pem, const char *algorithm);

#endif
