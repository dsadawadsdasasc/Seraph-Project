/* payload_entry.c — Implementation of `PayloadMain`, exported by svc.dll.
 *
 * Lifecycle (called from the manual-mapped entry of svc.dll):
 *
 *   stub_entry → manual-map svc.dll → DllMain(ATTACH) → PayloadMain(ctx)
 *
 *   1. Validate ctx (magic / abi / size).  Refuse mismatched stub.
 *   2. Install ctx->LogFn into a payload-internal global so all existing
 *      WriteLogFile calls reach the stub-provided sink (unified log).
 *   3. Cache identity (session_id, hwid, username) for AntiRE ban path.
 *   4. PayloadInitDriver() — load CtiIo64.sys + BYOVD_Init + EPROCESS spoof.
 *      If this fails the user gets a notification via the existing path and
 *      we return -2 so the stub can show "Driver Error" and exit.
 *   5. PayloadRunMenu(ctx) — runs the menu loop until user closes it.
 *      Internal cleanup (Patch_RestoreAll, AntiRE_Stop, BYOVD_Shutdown)
 *      runs before this returns.
 *   6. Return 0 (clean exit).
 *
 * The function is __cdecl to match the export in payload_entry.h and
 * matches what the stub side imports.  No SEH wraps the call sites here
 * because each underlying function has its own __try/__except; an
 * unhandled exception escaping PayloadMain would tear down the stub
 * which is the desired outcome (any state that violently fails this late
 * is unrecoverable).
 */
#include "payload_entry.h"
#include "payload_ctx.h"
#include "gui.h"          /* WriteLogFile (legacy default), PayloadInitDriver/PayloadRunMenu */
#include "antire.h"          /* AntiRE_Start (post-driver-init) */
#include "antire_handles.h"  /* P6.3 — hot-revert registration */
#include "patch.h"           /* Patch_RestoreAll */
#include "byovd.h"           /* BYOVD_SetInitCtx */
#include <string.h>

/* When linked into svc.dll, expose a payload-internal hook for the stub-
 * provided logger.  Existing TUs that call `WriteLogFile` reach the legacy
 * sink in gui.c (no-op).  We re-route by capturing ctx->LogFn into a
 * file-local function pointer the payload's own diagnostics can use.
 *
 * Future patch: replace WriteLogFile in every payload TU with a thin
 * indirection to g_payloadLogFn so all output funnels through the stub. */
static PayloadLogFn  g_payloadLogFn   = NULL;
static UINT32        g_payloadStubVer = 0;
static UINT32        g_payloadOwnVer  = 0;
static DWORD         g_payloadStubPid = 0;

/* Identity cache — exposed via accessors below.  Populated from ctx so
 * subsystems (antire ban path, future telemetry) can read without
 * re-passing ctx through every call chain. */
static char  g_payloadSessionId[PAYLOAD_CTX_SESSION_CCH] = {0};
static char  g_payloadHwid[PAYLOAD_CTX_HWID_CCH]         = {0};
static WCHAR g_payloadUsername[PAYLOAD_CTX_USERNAME_CCH] = {0};

/* Public accessors so payload TUs (antire, telemetry, etc.) read identity
 * without taking PayloadCtx as a parameter.  Returns NULL/0 if PayloadMain
 * was never invoked (legacy monolithic build). */
const char*  Payload_GetSessionId(void) { return g_payloadSessionId[0] ? g_payloadSessionId : NULL; }
const char*  Payload_GetHwid(void)      { return g_payloadHwid[0]      ? g_payloadHwid      : NULL; }
const WCHAR* Payload_GetUsername(void)  { return g_payloadUsername[0]  ? g_payloadUsername  : NULL; }
DWORD        Payload_GetStubPid(void)   { return g_payloadStubPid; }
UINT32       Payload_GetStubVer(void)   { return g_payloadStubVer; }
UINT32       Payload_GetOwnVer(void)    { return g_payloadOwnVer; }

/* Forwarder: if the stub gave us a logger, route to it; else no-op (matches
 * legacy `void WriteLogFile(const char*){ (void)msg; }` in gui.c). */
void Payload_Log(const char* msg) {
    if (g_payloadLogFn && msg) g_payloadLogFn(msg);
}

/* ── PayloadMain ───────────────────────────────────────────────────────────
 * Convenience macro: call ctx->LogFn directly, bypassing g_payloadLogFn.
 * This is the most reliable path back to the stub's seraph.log writer. */
#define CTX_LOG(msg) do { if (ctx && ctx->LogFn) ctx->LogFn(msg); } while(0)

PAYLOAD_API int __cdecl PayloadMain(const PayloadCtx* ctx) {
    /* 1. Validate. */
    if (!PayloadCtx_Valid(ctx)) {
        /* ctx->LogFn may be valid even if other fields fail — try it */
        if (ctx && ctx->LogFn) {
            char _b[192];
            wsprintfA(_b, "PayloadMain: ABI FAIL magic=0x%08X(exp=0x%08X) abi=%u(exp=%u) cb=%u(exp=%u)",
                ctx->magic, PAYLOAD_CTX_MAGIC,
                ctx->abi_version, PAYLOAD_ABI_VERSION,
                ctx->cbSize, (UINT32)sizeof(PayloadCtx));
            ctx->LogFn(_b);
        }
        return -1;
    }

    /* 2. Install global logger + identity. */
    g_payloadLogFn   = ctx->LogFn;
    g_payloadStubPid = ctx->stub_pid;
    g_payloadStubVer = ctx->stub_build_ver;
    g_payloadOwnVer  = ctx->payload_build_ver;

    CTX_LOG("PayloadMain: ENTER ctx valid");  /* direct call - no indirection */

    /* 3. Cache identity. */
    {
        size_t n;
        n = strnlen_s(ctx->session_id, PAYLOAD_CTX_SESSION_CCH - 1);
        memcpy(g_payloadSessionId, ctx->session_id, n);
        g_payloadSessionId[n] = 0;

        n = strnlen_s(ctx->hwid, PAYLOAD_CTX_HWID_CCH - 1);
        memcpy(g_payloadHwid, ctx->hwid, n);
        g_payloadHwid[n] = 0;

        {
            size_t i = 0;
            while (i < (PAYLOAD_CTX_USERNAME_CCH - 1) && ctx->username[i]) {
                g_payloadUsername[i] = ctx->username[i];
                i++;
            }
            g_payloadUsername[i] = 0;
        }
    }

    /* 4. Driver bring-up. */
    CTX_LOG("PayloadMain: calling BYOVD_SetInitCtx");
    BYOVD_SetInitCtx(ctx);
    CTX_LOG("PayloadMain: calling PayloadInitDriver");
    if (!PayloadInitDriver()) {
        CTX_LOG("PayloadMain: PayloadInitDriver FAILED");
        {
            char buf[64]; wsprintfA(buf, "PayloadMain: BYOVD failed at step %d", (int)g_byovdDiagStep);
            CTX_LOG(buf);
        }
        return -2;
    }
    CTX_LOG("PayloadMain: driver OK");

    /* 4.1 Hot-revert callback. */
    // CTX_LOG("PayloadMain: Pre SetHotRevertFn");
    // if (ctx->SetHotRevertFn) {
    //     CTX_LOG("PayloadMain: Calling ctx->SetHotRevertFn");
    //     ctx->SetHotRevertFn(Patch_RestoreAll);
    // } else {
    //     CTX_LOG("PayloadMain: Calling local AntiRE_Handles_SetHotRevert");
    //     AntiRE_Handles_SetHotRevert(Patch_RestoreAll);
    // }
    // CTX_LOG("PayloadMain: Post SetHotRevertFn");

    /* Close loading screen — driver is up. */
    CTX_LOG("PayloadMain: closing loading screen");
    if (ctx->CloseLoadingScreenFn) {
        CTX_LOG("PayloadMain: Calling ctx->CloseLoadingScreenFn");
        ctx->CloseLoadingScreenFn();
    }
    CTX_LOG("PayloadMain: Post CloseLoadingScreenFn");

    /* 5. AntiRE monitoring. */
    CTX_LOG("PayloadMain: starting AntiRE");
    AntiRE_Start();

    /* 6. Menu lifecycle (blocks until user closes). */
    CTX_LOG("PayloadMain: entering PayloadRunMenu");
    PayloadRunMenu(ctx);

    CTX_LOG("PayloadMain: EXIT clean");
    return 0;
}

#undef CTX_LOG
