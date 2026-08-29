
/*
 * config_crypto.c - AES-256 CBC encryption for configuration file
 */

#include "ThemidaSDK.h"
#include "config_crypto.h"
#include "debug.h"
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define KEY_SIZE 32          // AES-256
#define IV_SIZE  16          // AES block size
#define BLOCK_SIZE 16

// Generate hardware fingerprint based key — DETERMINISTIC (no time-based entropy)
BOOL GetConfigKey(BYTE key[32]) {
    // Collect system-specific identifiers
    DWORD volumeSerial = 0;
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD computerNameSize = sizeof(computerName) / sizeof(computerName[0]);
    SYSTEM_INFO sysInfo = {0};

    // Volume serial of C: drive
    GetVolumeInformationW(L"C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);

    // Computer name
    GetComputerNameW(computerName, &computerNameSize);

    // System info (processor architecture, page size)
    GetSystemInfo(&sysInfo);

    // Combine all sources into a buffer — all are stable across runs on the same machine
    BYTE fingerprint[256];
    DWORD offset = 0;

    *(DWORD*)(fingerprint + offset) = volumeSerial;
    offset += sizeof(volumeSerial);

    {
        DWORD _cnBytes = computerNameSize * sizeof(WCHAR);
        for (DWORD _i = 0; _i < _cnBytes; _i++)
            fingerprint[offset + _i] = ((const BYTE*)computerName)[_i];
        offset += _cnBytes;
    }

    *(DWORD*)(fingerprint + offset) = sysInfo.dwProcessorType;
    offset += sizeof(DWORD);

    *(DWORD*)(fingerprint + offset) = sysInfo.dwNumberOfProcessors;
    offset += sizeof(DWORD);


    // Hash the fingerprint using SHA-256 (via BCrypt)
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BOOL success = FALSE;

    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptOpenAlgorithmProvider failed", status);
        goto cleanup;
    }

    status = BCryptCreateHash(hHashAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptCreateHash failed", status);
        goto cleanup;
    }

    status = BCryptHashData(hHash, fingerprint, offset, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptHashData failed", status);
        goto cleanup;
    }

    status = BCryptFinishHash(hHash, key, KEY_SIZE, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptFinishHash failed", status);
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);

    /* Zero fingerprint material — contains volume serial, computer name, processor info.
     * Must not linger on stack after this frame returns. */
    SecureZeroMemory(fingerprint, sizeof(fingerprint));

    // Fallback to a deterministic but non-static key if hashing fails.
    // Caller still gets a usable key (so config decryption can proceed in the
    // worst case), but the return value reports the real status.
    if (!success) {
        memset(key, 0, KEY_SIZE);
        for (DWORD i = 0; i < offset && i < KEY_SIZE; i++) {
            key[i % KEY_SIZE] ^= fingerprint[i];
        }
    }

    return success;
}

#pragma optimize("", off)
BOOL ConfigEncrypt(const BYTE* plain, DWORD plainSize, BYTE* out, DWORD* outSize) {
    MUTATE_START
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL success = FALSE;
    BYTE iv[IV_SIZE] = {0};
    BYTE key[KEY_SIZE] = {0};
    DWORD cipherSize = 0;

    // Derive key from hardware fingerprint
    if (!GetConfigKey(key)) {
        DEBUG_ERROR("GetConfigKey failed");
        goto cleanup;
    }

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptOpenAlgorithmProvider failed", status);
        goto cleanup;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptSetProperty failed", status);
        goto cleanup;
    }

    // Generate random IV
    status = BCryptGenRandom(NULL, iv, IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptGenRandom failed", status);
        goto cleanup;
    }

    // Import key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        key, KEY_SIZE, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptGenerateSymmetricKey failed", status);
        goto cleanup;
    }

    // Calculate required cipher size
    status = BCryptEncrypt(hKey, (PUCHAR)plain, plainSize, NULL,
                           iv, IV_SIZE, NULL, 0, &cipherSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        DEBUG_NTSTATUS("BCryptEncrypt (size query) failed", status);
        goto cleanup;
    }

    if (*outSize < IV_SIZE + cipherSize) {
        *outSize = IV_SIZE + cipherSize;
        status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    // Copy IV to output
    for (DWORD _i = 0; _i < IV_SIZE; _i++) out[_i] = iv[_i];

    // Encrypt
    status = BCryptEncrypt(hKey, (PUCHAR)plain, plainSize, NULL,
                           iv, IV_SIZE, out + IV_SIZE, cipherSize, &cipherSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptEncrypt failed", status);
        goto cleanup;
    }

    *outSize = IV_SIZE + cipherSize;
    success = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    /* Zero key material from stack — derived from HWID, must not survive call frame.
     * SecureZeroMemory is not optimized away by the compiler (unlike memset). */
    SecureZeroMemory(key, KEY_SIZE);
    SecureZeroMemory(iv,  IV_SIZE);
    MUTATE_END
    return success;
}
#pragma optimize("", on)

#pragma optimize("", off)
BOOL ConfigDecrypt(const BYTE* cipher, DWORD cipherSize, BYTE* out, DWORD* outSize) {
    MUTATE_START
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL success = FALSE;
    BYTE iv[IV_SIZE]  = {0};  /* BUG FIX: initialize to zero — uninitialized iv causes
                               * garbage decrypt if cleanup is reached before IV extraction. */
    BYTE key[KEY_SIZE] = {0};
    DWORD plainSize = 0;

    if (cipherSize < IV_SIZE) {
        DEBUG_ERROR("Ciphertext too small (%u < %u)", cipherSize, IV_SIZE);
        goto cleanup;
    }

    // Extract IV
    for (DWORD _i = 0; _i < IV_SIZE; _i++) iv[_i] = cipher[_i];
    DWORD dataSize = cipherSize - IV_SIZE;

    // Derive key from hardware fingerprint
    if (!GetConfigKey(key)) {
        DEBUG_ERROR("GetConfigKey failed");
        goto cleanup;
    }

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptOpenAlgorithmProvider failed", status);
        goto cleanup;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptSetProperty failed", status);
        goto cleanup;
    }

    // Import key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        key, KEY_SIZE, 0);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptGenerateSymmetricKey failed", status);
        goto cleanup;
    }

    // Calculate required plaintext size
    status = BCryptDecrypt(hKey, (PUCHAR)(cipher + IV_SIZE), dataSize, NULL,
                           iv, IV_SIZE, NULL, 0, &plainSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        DEBUG_NTSTATUS("BCryptDecrypt (size query) failed", status);
        goto cleanup;
    }

    if (*outSize < plainSize) {
        *outSize = plainSize;
        status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    // Decrypt
    status = BCryptDecrypt(hKey, (PUCHAR)(cipher + IV_SIZE), dataSize, NULL,
                           iv, IV_SIZE, out, plainSize, &plainSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        DEBUG_NTSTATUS("BCryptDecrypt failed", status);
        goto cleanup;
    }

    *outSize = plainSize;
    success = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    /* Zero key material from stack — derived from HWID, must not survive call frame. */
    SecureZeroMemory(key, KEY_SIZE);
    SecureZeroMemory(iv,  IV_SIZE);
    MUTATE_END
    return success;
}
#pragma optimize("", on)

