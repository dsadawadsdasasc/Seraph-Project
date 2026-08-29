/* stub_login.h — Login phase exposed by Stub.exe.
 *
 * Stub_RunLoginPhase() drives the D2D login window, runs KeyAuth, and
 * returns the captured credentials + KeyAuth session/hwid back to the
 * stub entry.  The stub then proceeds to download/decrypt/manual-map the
 * payload and hand the resulting PayloadCtx to PayloadMain.
 *
 * In the NEW architecture, login is the ONLY thing the stub does that
 * touches user UI before the payload is mapped.  The driver (CtiIo64.sys)
 * is loaded by the payload, not the stub.  This isolates the stub's
 * surface area to: mutex, checks, login, transport, crypto, mapper.
 *
 * Backward compatibility: gui.c::ShowMainGUI also calls Stub_RunLoginPhase
 * (replacing its old in-place login loop).  Single source of truth.
 */
#ifndef SERAPH_STUB_LOGIN_H
#define SERAPH_STUB_LOGIN_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result of a successful login.  All fields populated on TRUE return.
 * - username/key are what the user typed (DPAPI-saved by Stub_RunLoginPhase).
 * - session_id is the KeyAuth session token (used by antire ban path).
 * - hwid is the same hex string KeyAuth was given (same hash function).
 * - aes_key/hmac_key are populated only after Phase 3.3 lands; in earlier
 *   builds they remain zeroed.  See KeyAuth_GetPayloadKeys.
 *
 * All buffers null-terminated.  Caller MUST `SecureZeroMemory` the
 * struct after use, especially the key fields. */
typedef struct StubLoginResult {
    WCHAR username[64];
    WCHAR key[128];           /* the typed license key — for DPAPI re-save */
    char  session_id[128];    /* KeyAuth session (post-auth) */
    char  hwid[64];           /* hex hwid generated for KeyAuth */

    /* Populated by Phase 3.3 (KeyAuth_GetPayloadKeys).  In Phase 1 builds
     * these stay zero and the stub falls back to LoadLibrary on a local
     * svc.dll. */
    BYTE  aes_key[32];        /* AES-256-GCM */
    BYTE  hmac_key[32];       /* HMAC-SHA256 */
    UINT32 min_stub_version;  /* manifest gate: stub older than this aborts */
    UINT32 payload_version;   /* informational */
} StubLoginResult;

/* Run the login UI loop.  Blocks until either:
 *   - User authenticates successfully → returns TRUE, fills `out`
 *   - User closes the window or Overlay_Stop fires → returns FALSE
 * Internally triggers DPAPI cred save on success.
 *
 * `out` MUST point to a writable buffer.  On FALSE return, contents of
 * `out` are undefined (do not consume). */
BOOL Stub_RunLoginPhase(StubLoginResult* out);

/* Run the loading phase UI loop. Kept separate from login so the Stub
 * can download, decrypt, map and initialize on a background thread while
 * keeping the UI responsive. MUST be called on the same thread that
 * called Stub_RunLoginPhase or where the Overlay was created on. */
void Stub_RenderLoadingPhase(void);

/* Update the text shown on the loading screen. Thread-safe. */
void Stub_SetLoadingText(const wchar_t* text);

/* Spoof the current process's PEB ProcessParameters image/cmdline to
 * `RuntimeBroker.exe` so casual EnumProcesses-style scanners see a
 * legit-looking entry.  Idempotent.  Called by stub_entry before the
 * login UI shows.
 *
 * NOTE: In the legacy monolithic flow this lived inside gui.c::ShowMainGUI
 * as a static helper.  Exposed here so the new Stub.exe entry can invoke
 * it independently of ShowMainGUI. */
void Stub_SpoofProcessName(void);

/* Load DPAPI-encrypted creds from %APPDATA%\Microsoft\Devices\a.dat.
 * Returns TRUE if the file exists, decrypted successfully, and both
 * fields fit in the provided buffers.  Caller passes 64-WCHAR user and
 * 128-WCHAR key buffers. */
BOOL Stub_LoadSavedCreds(WCHAR* user64, WCHAR* key128);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_STUB_LOGIN_H */
