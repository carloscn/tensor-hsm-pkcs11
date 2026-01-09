# Secure HSM PKCS#11 Module

A PKCS#11 module implementation based on [empty-pkcs11](https://github.com/Pkcs11Interop/empty-pkcs11) framework that wraps an HTTPS-based signing service. This module allows PKCS#11-compatible applications to use a remote signing service as if it were a local cryptographic token.

## Features

- PKCS#11 v2.40 compatible interface (based on empty-pkcs11 framework)
- HTTPS-based remote signing service integration
- JSON-based communication protocol
- Thread-safe implementation
- Minimal dependencies
- Based on proven empty-pkcs11 framework structure

## Requirements

- Ubuntu AMD64 (or compatible Linux distribution)
- GCC compiler
- libcurl (for HTTPS requests)
- OpenSSL (for base64 encoding/decoding and crypto operations)
- pthread (for thread safety)

## Installation

### Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential libcurl4-openssl-dev libssl-dev opensc
```

### Build the Module

```bash
cd build/linux
make
```

This will create `libsecure_pkcs11_https.so` in the `build/linux/` directory.

### Install the Module (Optional)

```bash
sudo cp build/linux/libsecure_pkcs11_https.so /usr/lib/x86_64-linux-gnu/pkcs11/
```

## Configuration

The module uses environment variables for configuration:

**Required:**
- `PKCS11_CLIENT_CERT`: Path to client certificate file (PEM format) for mTLS authentication
- `PKCS11_CLIENT_KEY`: Path to client private key file (PEM format) for mTLS authentication

**Optional:**
- `PKCS11_SIGNING_URL`: Base URL of signing service (required, no default)
- `PKCS11_SIGNING_ENV`: Environment - "test" or "prod" (default: "test")
- `PKCS11_SSL_NO_VERIFY`: Set to "1" to disable SSL verification (testing only)

**Example:**
```bash
export PKCS11_SIGNING_URL=<your-signing-service-url>
export PKCS11_CLIENT_CERT=/path/to/tester.crt
export PKCS11_CLIENT_KEY=/path/to/tester.key
export PKCS11_SIGNING_ENV=test
```

### Default Certificate Location

The module will automatically use certificates from `/etc/secure/pki/` if environment variables are not set:

```bash
sudo mkdir -p /etc/secure/pki
sudo cp /path/to/client.crt /etc/secure/pki/client.crt
sudo cp /path/to/client.key /etc/secure/pki/client.key
sudo chmod 644 /etc/secure/pki/client.crt
sudo chmod 600 /etc/secure/pki/client.key
```

## Supported Algorithms

| Algorithm | Key ID (CKA_ID) | Mechanism | Algorithm String |
|-----------|----------------|-----------|------------------|
| RSA2048 PKCS#1 v1.5 | 0x01 | CKM_RSA_PKCS | `rsa-sign-pkcs1-2048-sha256` |
| RSA2048 PSS | 0x02 | CKM_RSA_PKCS_PSS | `rsa-sign-pss-2048-sha256` |
| RSA3072 PSS | 0x03 | CKM_RSA_PKCS_PSS | `rsa-sign-pss-3072-sha256` |
| ECDSA secp256r1 | 0x04 | CKM_ECDSA | `ec-sign-secp256r1-sha256` |

## Usage

### Using pkcs11-tool (OpenSC)

```bash
# Show module info
pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --show-info

# List slots
pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --list-slots

# List objects (keys)
pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --list-objects

# Sign data (RSA2048-SHA256)
pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --sign \
    --input-file data.bin \
    --output-file signature.bin \
    --mechanism SHA256-RSA-PKCS \
    --id 01
```

### Using Test Scripts

```bash
# Test RSA2048 PKCS#1
./tests/test_rsa2048_pkcs1.sh

# Test RSA2048 PSS
./tests/test_rsa2048_pss.sh

# Test RSA3072 PSS
./tests/test_rsa3072_pss.sh

# Test ECDSA
./tests/test_ecdsa.sh

# Test OpenSSL Engine integration
./tests/test_openssl_engine_cmd.sh
```

## Testing

### Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a 5-minute setup guide.

### Detailed Documentation

- [USER_MANUAL.md](USER_MANUAL.md) - Complete user guide
- [UNIT_DESIGN.md](UNIT_DESIGN.md) - Technical design documentation
- [tests/RUN_OPENSSL_TEST.md](tests/RUN_OPENSSL_TEST.md) - OpenSSL engine testing guide

### Running Tests

```bash
# Set up environment
export PKCS11_SIGNING_URL=<your-signing-service-url>
export PKCS11_CLIENT_CERT=/path/to/client.crt
export PKCS11_CLIENT_KEY=/path/to/client.key
export PKCS11_SIGNING_ENV=test

# Run individual test scripts
cd tests
./test_rsa2048_pkcs1.sh
./test_openssl_engine_cmd.sh
```

## Project Structure

```
secure-hsm-pkcs11/
├── README.md              # This file
├── QUICKSTART.md          # Quick start guide
├── USER_MANUAL.md         # User manual
├── UNIT_DESIGN.md         # Design documentation
├── LICENSE.md             # Apache License 2.0
├── src/
│   ├── empty-pkcs11.c     # Main PKCS#11 implementation
│   ├── empty-pkcs11.h     # Header file
│   ├── https_client.c     # HTTPS client for signing service
│   ├── https_client.h     # HTTPS client header
│   └── cryptoki/
│       └── pkcs11.h       # PKCS#11 header definitions
├── build/
│   └── linux/
│       ├── Makefile       # Build configuration
│       └── empty-pkcs11.version  # Version script
└── tests/
    ├── test_rsa2048_pkcs1.sh
    ├── test_rsa2048_pss.sh
    ├── test_rsa3072_pss.sh
    ├── test_ecdsa.sh
    ├── test_openssl_engine_cmd.sh
    └── RUN_OPENSSL_TEST.md
```

## Implementation Details

### Based on empty-pkcs11 Framework

This implementation is based on the [empty-pkcs11](https://github.com/Pkcs11Interop/empty-pkcs11) framework, which provides a minimal PKCS#11 v2.40 skeleton. We've integrated HTTPS signing functionality while maintaining the framework's structure and compatibility.

### Supported PKCS#11 Functions

- `C_Initialize` / `C_Finalize` - Module initialization
- `C_GetInfo` - Module information
- `C_GetFunctionList` - Function list retrieval
- `C_GetSlotList` / `C_GetSlotInfo` / `C_GetTokenInfo` - Slot and token management
- `C_GetMechanismList` / `C_GetMechanismInfo` - Mechanism information
- `C_OpenSession` / `C_CloseSession` - Session management
- `C_Login` / `C_Logout` - Authentication (minimal implementation)
- `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` - Object enumeration
- `C_GetAttributeValue` - Attribute retrieval
- `C_SignInit` / `C_Sign` - Signing operations
- `C_VerifyInit` / `C_Verify` - Verification operations

### Algorithm Selection

The module creates multiple key objects, one for each supported algorithm. To select a specific algorithm:

1. **Using C_FindObjects with CKA_ID:**
   ```c
   CK_ATTRIBUTE template[] = {
       {CKA_CLASS, &(CK_ULONG){CKO_PRIVATE_KEY}, sizeof(CK_ULONG)},
       {CKA_ID, &(CK_BYTE){0x01}, sizeof(CK_BYTE)}  // 0x01 = RSA2048 PKCS#1
   };
   C_FindObjectsInit(hSession, template, 2);
   C_FindObjects(hSession, &hKey, 1, &ulObjectCount);
   ```

2. **Using pkcs11-tool:**
   ```bash
   # List all keys
   pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --list-objects
   
   # Sign with specific key (use --id to select by CKA_ID)
   pkcs11-tool --module ./build/linux/libsecure_pkcs11_https.so --sign \
       --id 01 --input-file data.bin --output-file sig.bin
   ```

## Limitations

This is a minimal implementation with the following limitations:

1. **Single Slot**: Only one slot (slot 0) is supported
2. **Multiple Keys**: Four key objects are created (one per algorithm), identified by `CKA_ID`
3. **No PIN Management**: PIN authentication is accepted but not validated
4. **PSS Algorithms**: RSA PSS algorithms require multipart/form-data format, which is not yet fully implemented
5. **Verification**: Signature verification requires public key retrieval from HTTPS service
6. **Connectivity Test**: URL connectivity test in `C_Initialize` may fail if service is temporarily unavailable (warning only)

## Security Considerations

- The module uses HTTPS for communication but does not implement certificate pinning
- PIN authentication is not enforced (all logins are accepted)
- No key material is stored locally - all signing is done remotely
- Consider implementing proper authentication and authorization in production

## License

This project is based on [empty-pkcs11](https://github.com/Pkcs11Interop/empty-pkcs11) which is available under the [Apache License, Version 2.0](LICENSE.md).

## Acknowledgments

- Based on [empty-pkcs11](https://github.com/Pkcs11Interop/empty-pkcs11) by [Jaroslav Imrich](https://www.jimrich.sk/)
- Part of the [Pkcs11Interop](https://www.pkcs11interop.net/) project

## Troubleshooting

### Module not found

Ensure the module path is correct:
```bash
ls -la build/linux/libsecure_pkcs11_https.so
```

### Signing fails

1. Check that `PKCS11_SIGNING_URL` is set correctly
2. Verify the signing service is accessible
3. Check network connectivity and SSL certificates
4. Review signing service logs

### Build errors

Ensure all dependencies are installed:
```bash
sudo apt-get install -y build-essential libcurl4-openssl-dev libssl-dev
```

### OpenSSL Engine Testing

See [tests/RUN_OPENSSL_TEST.md](tests/RUN_OPENSSL_TEST.md) for detailed instructions on testing with OpenSSL engine.
