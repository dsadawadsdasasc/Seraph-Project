/* stub_crypto.h — AES-256-GCM decrypt + HMAC-SHA256 verify via BCrypt.
 *
 * Used by Stub.exe to verify + decrypt the encrypted svc.dll blob downloaded
 * from GitHub.  Keys are obtained from KeyAuth (type=var) post-auth.
 *
 * Wire format expected (binary, little-endian):
 *   [0..31]    HMAC-SHA256 over (salt || iv || tag || ciphertext)
 *   [32..47]   salt (16 bytes, currently unused but reserved for KDF)
 *   [48..59]   IV (12 bytes, AES-GCM nonce)
 *   [60..75]   GCM tag (16 bytes)
 *   [76..N-1]  ciphertext
 *
 * Returned plaintext is the raw payload DLL bytes ready for LoadLibrary or
 * manual map.  Caller must free via Stub_FreeBuf().
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STUB_HMAC_SIZE   32
#define STUB_SALT_SIZE   16
#define STUB_IV_SIZE     12
#define STUB_TAG_SIZE    16
#define STUB_HEADER_SIZE (STUB_HMAC_SIZE + STUB_SALT_SIZE + STUB_IV_SIZE + STUB_TAG_SIZE) /* 76 */

/* Verify HMAC then AES-GCM decrypt.
 *  - in/inLen      = full blob (header + ciphertext)
 *  - aes_key       = 32 bytes
 *  - hmac_key      = 32 bytes
 *  - outPlain      = receives malloc'd buffer (caller frees via Stub_FreeBuf)
 *  - outPlainLen   = receives plaintext length
 * Returns 0 on success, negative error code otherwise:
 *   -1 input too small / bad args
 *   -2 HMAC mismatch (tampered or wrong key)
 *   -3 AES-GCM auth failure (tag mismatch)
 *   -4 BCrypt API failure
 */
int  Stub_VerifyAndDecrypt(const BYTE* in, SIZE_T inLen,
                           const BYTE aes_key[32], const BYTE hmac_key[32],
                           BYTE** outPlain, SIZE_T* outPlainLen);

void Stub_FreeBuf(BYTE* p, SIZE_T len);  /* zeros memory before free */

#ifdef __cplusplus
}
#endif
