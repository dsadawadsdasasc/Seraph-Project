#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encrypts plaintext of size plainSize, writes ciphertext (IV + cipher) to out.
// Returns TRUE on success, FALSE on failure.
// out must be at least plainSize + 16 bytes (for IV and padding).
BOOL ConfigEncrypt(const BYTE* plain, DWORD plainSize, BYTE* out, DWORD* outSize);

// Decrypts ciphertext (IV + cipher) of size cipherSize, writes plaintext to out.
// Returns TRUE on success, FALSE on failure.
BOOL ConfigDecrypt(const BYTE* cipher, DWORD cipherSize, BYTE* out, DWORD* outSize);

// Generates a static key (for demo). In production, derive from hardware fingerprint.
BOOL GetConfigKey(BYTE key[32]);

#ifdef __cplusplus
}
#endif