/* stub_crypto.c — AES-256-GCM + HMAC-SHA256 via BCrypt (CNG).
 *
 * Pure user-mode crypto.  No OpenSSL, no DLL drop, no MEM_PRIVATE/EXEC
 * pages — BCrypt lives in bcrypt.dll (system module), so all keying material
 * stays inside an already-loaded image.
 *
 * Wire format documented in stub_crypto.h.
 *
 * NOTE: We zero key/IV/plaintext buffers on every error path.  The plaintext
 * buffer returned to the caller is heap-allocated and must be released via
 * Stub_FreeBuf() which RtlSecureZeroMemory's before HeapFree.
 */
#include "stub_crypto.h"
#include "ThemidaSDK.h"
#include <bcrypt.h>
#include <ntstatus.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* WriteLogFile is provided by stub_log.c when SERAPH_BUILD_STUB. */
extern void WriteLogFile(const char* msg);

static int hmac_verify(const BYTE hmac_key[32],
                       const BYTE* expected,    /* 32 bytes */
                       const BYTE* msg, SIZE_T msgLen)
{
    MUTATE_START
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE computed[32] = {0};
    int rc = -4;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                    NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) goto done;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0,
                    (PUCHAR)hmac_key, 32, 0))) goto done;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)msg, (ULONG)msgLen, 0))) goto done;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, computed, 32, 0))) goto done;

    /* Constant-time compare */
    BYTE diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ expected[i];
    rc = (diff == 0) ? 0 : -2;

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    RtlSecureZeroMemory(computed, sizeof(computed));
    MUTATE_END
    return rc;
}

static int aes_gcm_decrypt(const BYTE aes_key[32],
                           const BYTE iv[12], const BYTE tag[16],
                           const BYTE* ct, SIZE_T ctLen,
                           BYTE* pt /* same size as ct */)
{
    MUTATE_START
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    int rc = -4;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                    (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) goto done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                    (PUCHAR)aes_key, 32, 0))) goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce       = (PUCHAR)iv;
    info.cbNonce       = 12;
    info.pbTag         = (PUCHAR)tag;
    info.cbTag         = 16;
    info.dwFlags       = 0;

    ULONG outLen = 0;
    NTSTATUS s = BCryptDecrypt(hKey,
                               (PUCHAR)ct, (ULONG)ctLen,
                               &info,
                               NULL, 0,
                               pt, (ULONG)ctLen, &outLen, 0);
    if (s == STATUS_AUTH_TAG_MISMATCH) { rc = -3; goto done; }
    if (!NT_SUCCESS(s))                { rc = -4; goto done; }
    rc = 0;

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    MUTATE_END
    return rc;
}

int Stub_VerifyAndDecrypt(const BYTE* in, SIZE_T inLen,
                          const BYTE aes_key[32], const BYTE hmac_key[32],
                          BYTE** outPlain, SIZE_T* outPlainLen)
{
    VM_START
    int rc_out = -1;
    if (!in || !aes_key || !hmac_key || !outPlain || !outPlainLen) { goto done; }
    if (inLen <= STUB_HEADER_SIZE) { goto done; }

    const BYTE* hmac_blob = in + 0;
    const BYTE* salt      = in + STUB_HMAC_SIZE;                                  /* 16 */
    const BYTE* iv        = in + STUB_HMAC_SIZE + STUB_SALT_SIZE;                 /* 12 */
    const BYTE* tag       = in + STUB_HMAC_SIZE + STUB_SALT_SIZE + STUB_IV_SIZE;  /* 16 */
    const BYTE* ct        = in + STUB_HEADER_SIZE;
    SIZE_T      ctLen     = inLen - STUB_HEADER_SIZE;
    (void)salt;  /* reserved for KDF in P3.3 */

    /* Step 1 — verify HMAC over (salt || iv || tag || ct).  HMAC bytes occupy
     * the first 32 bytes of the blob; everything after is what's signed. */
    int rc = hmac_verify(hmac_key, hmac_blob, in + STUB_HMAC_SIZE,
                         inLen - STUB_HMAC_SIZE);
    if (rc != 0) {
        WriteLogFile(rc == -2 ? "Stub_VerifyAndDecrypt: HMAC mismatch"
                              : "Stub_VerifyAndDecrypt: HMAC API failure");
        rc_out = rc;
        goto done;
    }

    /* Step 2 — allocate plaintext buffer and run AES-GCM decrypt. */
    BYTE* pt = (BYTE*)HeapAlloc(GetProcessHeap(), 0, ctLen);
    if (!pt) { rc_out = -4; goto done; }
    rc = aes_gcm_decrypt(aes_key, iv, tag, ct, ctLen, pt);
    if (rc != 0) {
        WriteLogFile(rc == -3 ? "Stub_VerifyAndDecrypt: GCM tag mismatch"
                              : "Stub_VerifyAndDecrypt: AES-GCM API failure");
        RtlSecureZeroMemory(pt, ctLen);
        HeapFree(GetProcessHeap(), 0, pt);
        rc_out = rc;
        goto done;
    }

    *outPlain    = pt;
    *outPlainLen = ctLen;
    rc_out = 0;

done:
    VM_END
    return rc_out;
}

void Stub_FreeBuf(BYTE* p, SIZE_T len) {
    if (!p) return;
    RtlSecureZeroMemory(p, len);
    HeapFree(GetProcessHeap(), 0, p);
}
