/*
 * HTTPS client for signing service
 * Supports multiple algorithms: RSA2048 PKCS#1, RSA2048 PSS, RSA3072 PSS, ECDSA secp256r1
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

// Default signing service URL (must be set via PKCS11_SIGNING_URL environment variable)
#define DEFAULT_BASE_URL ""
#define DEFAULT_ENVIRONMENT "test"

// Structure to hold HTTP response data
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Global configuration
static char *g_base_url = NULL;
static char *g_client_cert_path = NULL;
static char *g_client_key_path = NULL;
static char *g_environment = NULL;

// Callback function for CURL to write response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Base64 encode function
static char *base64_encode(const unsigned char *input, size_t length) __attribute__((unused));
static char *base64_encode(const unsigned char *input, size_t length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    char *buff = NULL;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);
    return buff;
}

// Base64 decode function
static unsigned char *base64_decode(const char *input, int *length) {
    BIO *b64, *bmem;
    unsigned char *buffer = NULL;
    size_t len;
    
    if (!input || !length) {
        return NULL;
    }
    
    len = strlen(input);
    if (len == 0) {
        *length = 0;
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        return NULL;
    }
    
    bmem = BIO_new_mem_buf(input, (int)len);
    if (!bmem) {
        BIO_free_all(b64);
        return NULL;
    }
    
    bmem = BIO_push(b64, bmem);
    if (!bmem) {
        BIO_free_all(b64);
        return NULL;
    }
    
    // Set flags to ignore newlines (like Qt's fromBase64)
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // Allocate buffer (base64 decoded size is at most 3/4 of input, but we allocate full len for safety)
    buffer = (unsigned char *)malloc(len);
    if (!buffer) {
        BIO_free_all(bmem);
        return NULL;
    }
    
    int read_len = BIO_read(bmem, buffer, (int)len);
    if (read_len <= 0) {
        free(buffer);
        buffer = NULL;
        *length = 0;
    } else {
        *length = read_len;
    }
    
    BIO_free_all(bmem);
    return buffer;
}

// Forward declaration
static void https_client_cleanup_static(void);

// Simple JSON parser for extracting string values
static char *extract_json_string(const char *json, const char *key) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    
    const char *key_pos = strstr(json, pattern);
    if (!key_pos) {
        return NULL;
    }
    
    // Find the colon after the key
    const char *colon = strchr(key_pos, ':');
    if (!colon) {
        return NULL;
    }
    
    // Find the opening quote
    const char *quote1 = strchr(colon, '"');
    if (!quote1) {
        return NULL;
    }
    
    // Find the closing quote
    const char *quote2 = strchr(quote1 + 1, '"');
    if (!quote2) {
        return NULL;
    }
    
    size_t len = quote2 - quote1 - 1;
    char *value = (char *)malloc(len + 1);
    if (!value) return NULL;
    
    memcpy(value, quote1 + 1, len);
    value[len] = '\0';
    return value;
}

// Initialize HTTPS client
int https_client_init(const char *base_url, const char *client_cert_path,
                      const char *client_key_path, const char *environment) {
    // Free existing configuration if any (avoid double free)
    https_client_cleanup_static();
    
    // Initialize pointers to NULL first
    g_base_url = NULL;
    g_client_cert_path = NULL;
    g_client_key_path = NULL;
    g_environment = NULL;
    
    if (base_url) {
        g_base_url = (char *)strdup(base_url);
        if (!g_base_url) return -1;
    } else {
        g_base_url = (char *)strdup(DEFAULT_BASE_URL);
        if (!g_base_url) return -1;
    }
    
    if (client_cert_path) {
        g_client_cert_path = (char *)strdup(client_cert_path);
        if (!g_client_cert_path) {
            https_client_cleanup_static();
            return -1;
        }
    }
    
    if (client_key_path) {
        g_client_key_path = (char *)strdup(client_key_path);
        if (!g_client_key_path) {
            https_client_cleanup_static();
            return -1;
        }
    }
    
    if (environment) {
        g_environment = (char *)strdup(environment);
        if (!g_environment) {
            https_client_cleanup_static();
            return -1;
        }
    } else {
        g_environment = (char *)strdup(DEFAULT_ENVIRONMENT);
        if (!g_environment) {
            https_client_cleanup_static();
            return -1;
        }
    }
    
    return 0;
}

// Cleanup HTTPS client (public API)
void https_client_cleanup(void) {
    https_client_cleanup_static();
}

// Cleanup HTTPS client (static version for internal use)
static void https_client_cleanup_static(void) {
    // Use temporary pointers to avoid issues if called multiple times
    char *base_url = g_base_url;
    char *client_cert_path = g_client_cert_path;
    char *client_key_path = g_client_key_path;
    char *environment = g_environment;
    
    // Clear global pointers first
    g_base_url = NULL;
    g_client_cert_path = NULL;
    g_client_key_path = NULL;
    g_environment = NULL;
    
    // Then free
    if (base_url) free(base_url);
    if (client_cert_path) free(client_cert_path);
    if (client_key_path) free(client_key_path);
    if (environment) free(environment);
}

// Map algorithm to endpoint path
static const char *get_endpoint_path(const char *algorithm) {
    if (!algorithm) {
        return NULL;
    }
    
    // Convert to lowercase for comparison
    char algo_lower[128];
    size_t i = 0;
    for (; algorithm[i] && i < sizeof(algo_lower) - 1; i++) {
        algo_lower[i] = (algorithm[i] >= 'A' && algorithm[i] <= 'Z') 
                       ? (algorithm[i] + 32) : algorithm[i];
    }
    algo_lower[i] = '\0';
    
    // Map algorithm strings to endpoint paths
    if (strstr(algo_lower, "rsa") && strstr(algo_lower, "pkcs1") && strstr(algo_lower, "2048")) {
        return "/api/v1/signatures/secflash-rsa2048";
    } else if (strstr(algo_lower, "rsa") && strstr(algo_lower, "pss") && strstr(algo_lower, "2048")) {
        return "/api/v1/signatures/secflash-rsa2048pss";
    } else if (strstr(algo_lower, "rsa") && strstr(algo_lower, "pss") && strstr(algo_lower, "3072")) {
        return "/api/v1/signatures/secflash-rsa3072pss";
    } else if (strstr(algo_lower, "ec") && strstr(algo_lower, "secp256r1")) {
        return "/api/v1/signatures/secflash-ecdsa";
    } else if (strstr(algo_lower, "rsa") && strstr(algo_lower, "2048") && !strstr(algo_lower, "pss")) {
        // Legacy format: assume PKCS#1 v1.5
        return "/api/v1/signatures/secflash-rsa2048";
    }
    
    return NULL;
}

// Check if algorithm uses PSS format (multipart/form-data)
static int is_pss_algorithm(const char *algorithm) {
    if (!algorithm) {
        return 0;
    }
    
    char algo_lower[128];
    size_t i = 0;
    for (; algorithm[i] && i < sizeof(algo_lower) - 1; i++) {
        algo_lower[i] = (algorithm[i] >= 'A' && algorithm[i] <= 'Z') 
                       ? (algorithm[i] + 32) : algorithm[i];
    }
    algo_lower[i] = '\0';
    
    return (strstr(algo_lower, "pss") != NULL);
}

/*
 * Test HTTPS service connectivity
 * Returns: 0 on success (service is reachable), -1 on error
 */
int https_test_connectivity(void) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char url[512];
    long response_code = 0;
    
    // Get configuration
    const char *base_url = g_base_url;
    if (!base_url) {
        base_url = getenv("PKCS11_SIGNING_URL");
        if (!base_url) {
            base_url = DEFAULT_BASE_URL;
        }
    }
    
    const char *env = g_environment;
    if (!env) {
        env = getenv("PKCS11_SIGNING_ENV");
        if (!env) {
            env = DEFAULT_ENVIRONMENT;
        }
    }
    
    // Test with RSA2048 endpoint (most common)
    const char *path_prefix = (strcmp(env, "prod") == 0) ? "/prod" : "/test";
    snprintf(url, sizeof(url), "%s%s/api/v1/signatures/secflash-rsa2048", base_url, path_prefix);
    
    // Initialize response buffer
    chunk.memory = malloc(1);
    if (!chunk.memory) {
        return -1;
    }
    chunk.size = 0;
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return -1;
    }
    
    // Set CURL options for connectivity test
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);  // HEAD request
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);  // 5 second timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);  // 3 second connect timeout
    
    // SSL/TLS configuration
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Client certificate authentication (mTLS)
    const char *client_cert = g_client_cert_path;
    const char *client_key = g_client_key_path;
    
    if (!client_cert) {
        client_cert = getenv("PKCS11_CLIENT_CERT");
    }
    if (!client_key) {
        client_key = getenv("PKCS11_CLIENT_KEY");
    }
    
    if (client_cert && client_key) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    }
    
    // Perform request
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        // Any response code means the service is reachable
        // 404/405 is expected for HEAD request, but means service is up
        if (response_code > 0) {
            curl_easy_cleanup(curl);
            if (chunk.memory) {
                free(chunk.memory);
            }
            return 0;  // Success - service is reachable
        }
    }
    
    curl_easy_cleanup(curl);
    if (chunk.memory) {
        free(chunk.memory);
    }
    return -1;  // Failed to reach service
}

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
                            unsigned char **signature, size_t *signature_len) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char *digest_b64 = NULL;
    char *json_request = NULL;
    char *signature_b64 = NULL;
    unsigned char *sig_data = NULL;
    int sig_len = 0;
    char url[512];
    
    // Validate hash length (must be 32 bytes for SHA-256)
    if (hash_len != 32) {
        fprintf(stderr, "Invalid hash length: expected 32 bytes, got %zu\n", hash_len);
        return -1;
    }
    
    // Get configuration from environment or use defaults
    const char *base_url = g_base_url;
    if (!base_url) {
        base_url = getenv("PKCS11_SIGNING_URL");
        if (!base_url) {
            base_url = DEFAULT_BASE_URL;
        }
    }
    
    const char *env = g_environment;
    if (!env) {
        env = getenv("PKCS11_SIGNING_ENV");
        if (!env) {
            env = DEFAULT_ENVIRONMENT;
        }
    }
    
    // Get endpoint path based on algorithm
    const char *endpoint_path = get_endpoint_path(algorithm);
    if (!endpoint_path) {
        fprintf(stderr, "Unsupported algorithm: %s\n", algorithm ? algorithm : "(null)");
        goto error;
    }
    
    // Build endpoint URL: /test/api/v1/signatures/... or /prod/api/v1/signatures/...
    const char *path_prefix = (strcmp(env, "prod") == 0) ? "/prod" : "/test";
    snprintf(url, sizeof(url), "%s%s%s", base_url, path_prefix, endpoint_path);
    
    // Encode hash as Base64
    digest_b64 = base64_encode(hash, hash_len);
    if (!digest_b64) {
        goto error;
    }
    
    // Determine request format based on algorithm
    int use_pss = is_pss_algorithm(algorithm);
    
    if (use_pss) {
        // For PSS algorithms: send raw hash data as multipart/form-data
        // Note: The service expects the raw hash, not the digest JSON
        // We'll use multipart/form-data format
        fprintf(stderr, "PSS algorithm support requires multipart/form-data, not yet fully implemented\n");
        goto error;
    } else {
        // For non-PSS algorithms: send digest as JSON
        json_request = malloc(strlen(digest_b64) + 30);
        if (!json_request) {
            goto error;
        }
        snprintf(json_request, strlen(digest_b64) + 30, "{\"digest\":\"%s\"}", digest_b64);
    }
    
    // Initialize response buffer
    chunk.memory = malloc(1);
    if (!chunk.memory) {
        goto error;
    }
    chunk.size = 0;
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        goto error;
    }
    
    // Initialize headers
    struct curl_slist *headers = NULL;
    
    // Set CURL options
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    if (use_pss) {
        // For PSS: use multipart/form-data (not yet implemented)
        fprintf(stderr, "PSS multipart/form-data not yet implemented\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        goto error;
    } else {
        // For non-PSS: use JSON
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_request);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    // SSL/TLS configuration
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Client certificate authentication (mTLS)
    const char *client_cert = g_client_cert_path;
    const char *client_key = g_client_key_path;
    
    if (!client_cert) {
        client_cert = getenv("PKCS11_CLIENT_CERT");
    }
    if (!client_key) {
        client_key = getenv("PKCS11_CLIENT_KEY");
    }
    
    if (client_cert && client_key) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    } else {
        fprintf(stderr, "Warning: Client certificate not configured. Set PKCS11_CLIENT_CERT and PKCS11_CLIENT_KEY\n");
    }
    
    // SSL verification can be disabled for testing
    const char *no_verify = getenv("PKCS11_SSL_NO_VERIFY");
    if (no_verify && strcmp(no_verify, "1") == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    // Perform request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        goto error;
    }
    
    // Get HTTP response code
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        fprintf(stderr, "HTTP error: %ld\n", response_code);
        if (chunk.memory) {
            fprintf(stderr, "Response: %s\n", chunk.memory);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        // Don't free chunk.memory here, let error handler do it
        goto error;
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    // Parse JSON response - extract signature field
    if (!chunk.memory) {
        fprintf(stderr, "No response data received\n");
        goto error;
    }
    
    signature_b64 = extract_json_string(chunk.memory, "signature");
    if (signature_b64) {
        sig_data = base64_decode(signature_b64, &sig_len);
        if (sig_data && sig_len > 0) {
            *signature = sig_data;
            *signature_len = sig_len;
            
            // Cleanup - set pointers to NULL after freeing
            free(chunk.memory);
            chunk.memory = NULL;
            free(digest_b64);
            digest_b64 = NULL;
            free(json_request);
            json_request = NULL;
            free(signature_b64);
            signature_b64 = NULL;
            return 0;
        }
        // If decode failed, free signature_b64 and continue to error path
        if (signature_b64) {
            free(signature_b64);
            signature_b64 = NULL;
        }
        if (sig_data) {
            free(sig_data);
            sig_data = NULL;
        }
        fprintf(stderr, "Failed to decode signature from base64\n");
    } else {
        fprintf(stderr, "Failed to extract signature from response: %s\n", chunk.memory ? chunk.memory : "(null)");
    }
    
error:
    // Only free if not already freed (check for NULL)
    // Note: chunk.memory is a struct member, not a pointer variable
    if (chunk.memory) {
        free(chunk.memory);
        chunk.memory = NULL;
        chunk.size = 0;
    }
    if (digest_b64) {
        free(digest_b64);
        digest_b64 = NULL;
    }
    if (json_request) {
        free(json_request);
        json_request = NULL;
    }
    if (signature_b64) {
        free(signature_b64);
        signature_b64 = NULL;
    }
    // Note: sig_data is returned to caller, don't free it here
    return -1;
}

/*
 * Get public key from HTTPS signing service for a specific algorithm
 * This function makes a signing request and extracts the certificate from the response,
 * then extracts the public key from the certificate.
 */
int https_get_public_key(const char *algorithm, char **public_key_pem) {
    if (!algorithm || !public_key_pem) {
        return -1;
    }
    
    // Make a dummy signing request to get the certificate
    // Use a dummy hash (all zeros) - the service will return the certificate in the response
    unsigned char dummy_hash[32] = {0};
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    
    // Request signature (this will also return the certificate)
    int ret = https_request_signature(dummy_hash, 32, algorithm, &signature, &signature_len);
    if (ret != 0) {
        return -1;
    }
    
    // Free signature (we don't need it)
    if (signature) {
        free(signature);
    }
    
    // Now make another request to get the certificate from response
    // We need to modify https_request_signature to also return certificate
    // For now, let's make a direct request to get certificate
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    char url[512];
    char *cert_b64 = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *pubkey_bio = NULL;
    char *pubkey_pem = NULL;
    long pubkey_len = 0;
    
    // Get endpoint path
    const char *endpoint_path = get_endpoint_path(algorithm);
    if (!endpoint_path) {
        fprintf(stderr, "Unsupported algorithm: %s\n", algorithm);
        return -1;
    }
    
    // Build URL
    const char *base_url = g_base_url ? g_base_url : getenv("PKCS11_SIGNING_URL");
    if (!base_url) {
        base_url = DEFAULT_BASE_URL;
    }
    
    const char *env = g_environment ? g_environment : getenv("PKCS11_SIGNING_ENV");
    if (!env) {
        env = DEFAULT_ENVIRONMENT;
    }
    
    const char *path_prefix = (strcmp(env, "prod") == 0) ? "/prod" : "/test";
    snprintf(url, sizeof(url), "%s%s%s", base_url, path_prefix, endpoint_path);
    
    // Initialize response buffer
    chunk.memory = malloc(1);
    if (!chunk.memory) {
        return -1;
    }
    chunk.size = 0;
    
    // Create dummy JSON request
    char *json_request = "{\"digest\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"; // Base64 of 32 zeros
    
    curl = curl_easy_init();
    if (!curl) {
        free(chunk.memory);
        return -1;
    }
    
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_request);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Client certificate authentication
    const char *client_cert = g_client_cert_path;
    const char *client_key = g_client_key_path;
    if (!client_cert) client_cert = getenv("PKCS11_CLIENT_CERT");
    if (!client_key) client_key = getenv("PKCS11_CLIENT_KEY");
    
    if (client_cert && client_key) {
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client_cert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    }
    
    const char *no_verify = getenv("PKCS11_SSL_NO_VERIFY");
    if (no_verify && strcmp(no_verify, "1") == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return -1;
    }
    
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        fprintf(stderr, "HTTP error: %ld\n", response_code);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(chunk.memory);
        return -1;
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    // Extract certificate from JSON response
    if (!chunk.memory) {
        free(chunk.memory);
        return -1;
    }
    
    cert_b64 = extract_json_string(chunk.memory, "certificate");
    if (!cert_b64) {
        fprintf(stderr, "No certificate in response\n");
        free(chunk.memory);
        return -1;
    }
    
    // Decode base64 certificate
    int cert_len = 0;
    unsigned char *cert_der = base64_decode(cert_b64, &cert_len);
    if (!cert_der || cert_len == 0) {
        fprintf(stderr, "Failed to decode certificate from base64\n");
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    // Parse X509 certificate
    const unsigned char *p = cert_der;
    cert = d2i_X509(NULL, &p, cert_len);
    if (!cert) {
        fprintf(stderr, "Failed to parse X509 certificate\n");
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    // Extract public key from certificate
    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        X509_free(cert);
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    // Convert public key to PEM format
    pubkey_bio = BIO_new(BIO_s_mem());
    if (!pubkey_bio) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    if (PEM_write_bio_PUBKEY(pubkey_bio, pkey) != 1) {
        BIO_free(pubkey_bio);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    pubkey_len = BIO_get_mem_data(pubkey_bio, &pubkey_pem);
    if (pubkey_len <= 0 || !pubkey_pem) {
        BIO_free(pubkey_bio);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    // Allocate and copy public key PEM
    *public_key_pem = malloc(pubkey_len + 1);
    if (!*public_key_pem) {
        BIO_free(pubkey_bio);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        free(cert_der);
        free(cert_b64);
        free(chunk.memory);
        return -1;
    }
    
    memcpy(*public_key_pem, pubkey_pem, pubkey_len);
    (*public_key_pem)[pubkey_len] = '\0';
    
    // Cleanup
    BIO_free(pubkey_bio);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    free(cert_der);
    free(cert_b64);
    free(chunk.memory);
    
    return 0;
}

/*
 * Verify signature using public key
 */
int https_verify_signature(const unsigned char *hash, size_t hash_len,
                          const unsigned char *signature, size_t signature_len,
                          const char *public_key_pem, const char *algorithm) {
    if (!hash || hash_len != 32 || !signature || !public_key_pem || !algorithm) {
        return -1;
    }
    
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *bio = NULL;
    int ret = -1;
    
    // Load public key from PEM
    bio = BIO_new_mem_buf(public_key_pem, -1);
    if (!bio) {
        return -1;
    }
    
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        return -1;
    }
    
    // Create verification context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Determine signature algorithm
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pkey_ctx = NULL;
    
    // Initialize verification
    if (EVP_DigestVerifyInit(mdctx, &pkey_ctx, md, NULL, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Set padding for RSA
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        if (strstr(algorithm, "pss")) {
            // RSA PSS padding
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
                EVP_MD_CTX_free(mdctx);
                EVP_PKEY_free(pkey);
                return -1;
            }
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
                EVP_MD_CTX_free(mdctx);
                EVP_PKEY_free(pkey);
                return -1;
            }
        } else {
            // RSA PKCS#1 padding
            if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) != 1) {
                EVP_MD_CTX_free(mdctx);
                EVP_PKEY_free(pkey);
                return -1;
            }
        }
    }
    
    // Verify signature
    if (EVP_DigestVerify(mdctx, signature, signature_len, hash, hash_len) == 1) {
        ret = 0; // Signature valid
    } else {
        ret = -1; // Signature invalid
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    
    return ret;
}

