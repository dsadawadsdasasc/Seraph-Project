/* payload_entry.h — Entry point exported by svc.dll.
 *
 * The stub manually maps svc.dll, then calls `PayloadMain` with a fully
 * populated PayloadCtx.  PayloadMain performs:
 *   1. Validate ctx (magic / abi / size)
 *   2. Install LogFn into a payload-internal global
 *   3. Cache identity (username, session_id, hwid) for antire
 *   4. Spoof EPROCESS image name (was done in old monolithic flow)
 *   5. Initialize BYOVD driver (CtiIo64.sys → BYOVD_Init)
 *   6. Launch menu loop (the original gui.c menu portion)
 *   7. On exit: restore patches, remove lazyhooks, BYOVD_Shutdown
 *
 * Returns:
 *   0  — normal exit (user closed menu)
 *  <0  — fatal error (invalid ctx, driver init failed, etc.)
 *  >0  — abnormal exit reserved for future signalling
 */
#ifndef SERAPH_PAYLOAD_ENTRY_H
#define SERAPH_PAYLOAD_ENTRY_H

#include "payload_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* When compiling svc.dll → export.
 * When compiling Stub.exe → import (so stub can resolve via mapped IAT).
 *
 * For monolithic backward-compat builds (current b.bat), neither macro is
 * set so PayloadMain has standard linkage. */
#if defined(SERAPH_BUILD_PAYLOAD)
#  define PAYLOAD_API __declspec(dllexport)
#elif defined(SERAPH_BUILD_STUB)
#  define PAYLOAD_API __declspec(dllimport)
#else
#  define PAYLOAD_API
#endif

PAYLOAD_API int __cdecl PayloadMain(const PayloadCtx* ctx);

/* Internal helper exposed for the monolithic backward-compat path: runs the
 * menu loop given an already-attached/initialised state.  Defined in the
 * payload's gui.c (see PayloadRunMenu). */
void PayloadRunMenu(const PayloadCtx* ctx);

/* Internal helper: BYOVD driver init.  Wraps the original
 * InitializeSeraphProduct + EPROCESS spoof, callable separately so the
 * monolithic flow keeps working without code duplication. */
BOOL PayloadInitDriver(void);

/* ── Identity accessors ────────────────────────────────────────────────────
 * Populated by PayloadMain from the stub-provided ctx.  Other payload TUs
 * (antire, telemetry, etc.) read these without re-passing ctx everywhere.
 * Return NULL/0 if PayloadMain was never invoked (legacy monolithic build). */
const char*  Payload_GetSessionId(void);
const char*  Payload_GetHwid(void);
const WCHAR* Payload_GetUsername(void);
DWORD        Payload_GetStubPid(void);
UINT32       Payload_GetStubVer(void);
UINT32       Payload_GetOwnVer(void);

/* Unified logger forwarder.  Routes to ctx->LogFn (set by stub) or no-op.
 * Existing payload TUs that call `WriteLogFile` continue to work unchanged
 * via the legacy sink in gui.c; new code SHOULD prefer Payload_Log. */
void Payload_Log(const char* msg);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_PAYLOAD_ENTRY_H */
