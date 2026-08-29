#pragma once
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib,"winhttp.lib")

typedef enum _KEYAUTH_RESULT {
    KEYAUTH_SUCCESS = 0,
    KEYAUTH_INVALID_KEY,
    KEYAUTH_KEY_ALREADY_USED,
    KEYAUTH_KEY_EXPIRED,
    KEYAUTH_KEY_BANNED,
    KEYAUTH_NO_SUBSCRIPTION,
    KEYAUTH_HWID_MISMATCH,
    KEYAUTH_NETWORK_ERROR,
    KEYAUTH_SERVER_ERROR,
    KEYAUTH_UNKNOWN_ERROR
} KEYAUTH_RESULT;

/* Returns detailed error code */
KEYAUTH_RESULT KeyAuthValidate(LPCWSTR key, wchar_t* errMsg, size_t errMsgSize);

/* Legacy boolean function (still used by existing code) */
BOOL KeyAuthLicense(LPCWSTR key);

/* Ban the currently logged-in session (HWID + IP blacklisted server-side).
 * Safe to call from any thread.  Returns TRUE if server acknowledged. */
BOOL KeyAuth_BanCurrentKey(void);

/* Close WinHTTP handles kept alive for ban capability.  Call on shutdown. */
void KeyAuth_Cleanup(void);

/* P3.3 — Fetch the encrypted payload keys after a successful login.
 * Issues a `type=var` request to KeyAuth for the variable named varName,
 * then expects the value to be a hex string of length (outLen*2).
 * Returns TRUE on success, FALSE on any failure (network, var missing,
 * length mismatch, hex decode).
 *
 *   - varName_a: variable name (ASCII), e.g. "aes_key", "hmac_key"
 *   - out:       receives raw bytes
 *   - outLen:    expected raw byte length (e.g. 32 for AES-256, 32 for HMAC)
 *
 * Requires that KeyAuthValidate() returned KEYAUTH_SUCCESS in this run
 * (relies on g_kaSession + g_hC + g_fOR still being valid).
 */
BOOL KeyAuth_GetPayloadKey(const char* varName_a, BYTE* out, int outLen);

/* P3.3 — Fetch min_stub_version variable as decimal string → uint32.
 * Returns 0 on failure; non-zero on success. */
UINT32 KeyAuth_GetMinStubVersion(void);

/* P7.2 — fetch arbitrary ASCII var (URL rotation, manifest path, etc).
 * Caller frees with free().  Returns NULL on failure. */
char* KeyAuth_GetVarString(const char* varName_a);

/* P3.8 — Read-only accessors to session/hwid persisted after a successful
 * KeyAuthValidate().  Both return pointers to internal static buffers
 * (valid until KeyAuth_Cleanup); empty string if no valid session. */
const char* KeyAuth_GetSessionId(void);
const char* KeyAuth_GetHwid(void);

extern wchar_t g_kaUsername[64];
