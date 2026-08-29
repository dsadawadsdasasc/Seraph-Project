/* payload_ctx.h — ABI contract between Stub.exe and svc.dll (PayloadMain).
 *
 * IMPORTANT: any layout change here REQUIRES bumping PAYLOAD_ABI_VERSION.
 * The payload validates `cbSize` and `abi_version` on entry and refuses to
 * run if either mismatches the stub it was paired with.  This protects
 * against running an old payload with a new stub (or vice-versa) that
 * happens to be downloaded due to caching / partial update.
 *
 * Header is included by BOTH Stub.exe (which builds the struct) AND
 * svc.dll (which receives a const pointer to it via PayloadMain).
 */
#ifndef SERAPH_PAYLOAD_CTX_H
#define SERAPH_PAYLOAD_CTX_H

#include <windows.h>
#include <winhttp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bump on ANY layout change.  Payload checks this matches; refuses to run
 * if mismatched.  Stub embeds at compile time. */
#define PAYLOAD_ABI_VERSION   3u

/* Magic at top of struct — sanity guard against junk pointers / partial
 * memory corruption during the manual-map handoff. */
#define PAYLOAD_CTX_MAGIC     0x53455241u  /* 'SERA' little-endian */

/* Log callback signature.  Stub provides; payload calls for unified logging.
 * NULL is allowed (no-op). */
typedef void (__cdecl *PayloadLogFn)(const char* msg);

/* Sizes of fixed-length char arrays embedded in PayloadCtx.  Externalised
 * so any consumer can refer to them without touching layout. */
#define PAYLOAD_CTX_USERNAME_CCH   64
#define PAYLOAD_CTX_SESSION_CCH    128
#define PAYLOAD_CTX_HWID_CCH       64

/* Forward-compatibility: leave 64 bytes of reserved tail.  Future fields go
 * here; older payloads ignore reserved bytes (kept zero-initialised by the
 * stub). */
#define PAYLOAD_CTX_RESERVED_BYTES 64

#pragma pack(push, 8)
typedef struct PayloadCtx {
    /* ── Identity / sanity ─────────────────────────────────────────────── */
    UINT32       magic;            /* must == PAYLOAD_CTX_MAGIC */
    UINT32       abi_version;      /* must == PAYLOAD_ABI_VERSION */
    UINT32       cbSize;           /* must == sizeof(PayloadCtx) */
    UINT32       _pad0;            /* keep 8-byte alignment for next ptrs */

    /* ── Stub identity (process info) ──────────────────────────────────── */
    HINSTANCE    hStubInstance;    /* GetModuleHandleW(NULL) of Stub.exe */
    DWORD        stub_pid;         /* GetCurrentProcessId() — used by antire */
    DWORD        _pad1;

    /* ── Payload mapping info (filled in by manual mapper) ─────────────── */
    PVOID        payloadBase;      /* base address of mapped svc.dll */
    SIZE_T       payloadSize;      /* SizeOfImage from PE headers */

    /* ── User identity (post-KeyAuth) ──────────────────────────────────── */
    WCHAR        username[PAYLOAD_CTX_USERNAME_CCH];   /* null-terminated */
    char         session_id[PAYLOAD_CTX_SESSION_CCH];  /* KeyAuth session */
    char         hwid[PAYLOAD_CTX_HWID_CCH];           /* hex hwid */

    /* ── Re-usable WinHTTP handles (so payload's antire ban doesn't need
     *    to re-authenticate / re-open connection).  May be NULL if the
     *    stub chose to close them; payload handles both cases. ────────── */
    HINTERNET    hWinhttpSession;
    HINTERNET    hWinhttpConnect;

    /* ── Logging callback (NULL = no-op) ───────────────────────────────── */
    PayloadLogFn LogFn;

    /* ── Stub-resident function pointers (P6.3 cross-boundary).
     *    Permitem que o payload registre callbacks no AntiRE_Handles que
     *    está rodando dentro do stub.  Sem isso, payload chamava sua
     *    própria cópia (svc.dll) do antire_handles, sem efeito. ──────── */
    void       (*SetHotRevertFn)(void (*fn)(void));   /* NULL se ausente */
    void       (*SetD2PidFn)(DWORD pid);              /* NULL se ausente */

    /* ── Versions / build info ─────────────────────────────────────────── */
    UINT32       stub_build_ver;       /* from Stub's build_stub_ver.txt */
    UINT32       payload_build_ver;    /* from manifest.json */

    /* Callback to close the loading screen before showing the menu */
    void (__cdecl *CloseLoadingScreenFn)(void);

    /* Callback to set dynamic loading text */
    void (__cdecl *SetLoadingTextFn)(const wchar_t* text);

    /* Reserved tail — keep last so future additions don't shift offsets */
    BYTE         reserved[PAYLOAD_CTX_RESERVED_BYTES - 16];
} PayloadCtx;
#pragma pack(pop)

/* Helper: zero-init + magic/version stamp.  Call from stub before filling. */
static __inline void PayloadCtx_Init(PayloadCtx* c) {
    if (!c) return;
    SecureZeroMemory(c, sizeof(*c));
    c->magic       = PAYLOAD_CTX_MAGIC;
    c->abi_version = PAYLOAD_ABI_VERSION;
    c->cbSize      = (UINT32)sizeof(PayloadCtx);
}

/* Helper: validate magic/version/size.  Call from payload's entry. */
static __inline BOOL PayloadCtx_Valid(const PayloadCtx* c) {
    if (!c) return FALSE;
    if (c->magic       != PAYLOAD_CTX_MAGIC)     return FALSE;
    if (c->abi_version != PAYLOAD_ABI_VERSION)   return FALSE;
    if (c->cbSize      != (UINT32)sizeof(PayloadCtx)) return FALSE;
    return TRUE;
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* SERAPH_PAYLOAD_CTX_H */
