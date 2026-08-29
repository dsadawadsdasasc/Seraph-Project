/* esp.c — Tiger Engine ESP: activates implementation from esp.h */
#define ESP_IMPLEMENTATION
#include "esp.h"
#include <windows.h>
#include <math.h>
#include "matchmaking.h"
#include "xor_strings.h"

#ifdef __cplusplus
extern "C" {
#endif
BOOL Overlay_GetMatchmakingActive(void);
#ifdef __cplusplus
}
#endif


/* ── Centralized ESP log — all ESP subsystem events go here ─────────────── */
#ifndef NDEBUG
void WriteEspLogExt(const char *msg) {
    char buf[768];
    wsprintfA(buf, "[ESP_EXT][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    OutputDebugStringA(buf);
}
#define ESPLOG(msg)        WriteEspLogExt(msg)
#define ESPLOGF(fmt, ...)  do { char _b[256]; wsprintfA(_b, fmt, __VA_ARGS__); WriteEspLogExt(_b); } while(0)
#else
#define ESPLOG(msg)        ((void)0)
#define ESPLOGF(fmt, ...)  ((void)0)
#endif

/* ── Schindler's List scanner ───────────────────────────────────────────── */
static UINT64 _rip_resolve(UINT64 va, int disp_off, int len, UINT64 cr3) {
    INT32 disp = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, va + (UINT64)disp_off, &disp, 4);
    BYOVD_UNLOCK();
    return va + (UINT64)len + (UINT64)(INT64)disp;
}

static UINT64 _aob_scan(UINT64 base, UINT64 size, const UINT8 *pat,
                         const UINT8 *mask, UINT32 plen, UINT64 cr3)
{
#define _CHUNK 4096
    UINT8 buf[_CHUNK + 32];
    for (UINT64 off = 0; off < size; off += _CHUNK) {
        UINT32 n = (UINT32)(size - off < _CHUNK + 32 ? size - off : _CHUNK + 32);
        BYOVD_LOCK();
        BOOL ok = BYOVD_ReadVA_NoCache(cr3, base + off, buf, n);
        BYOVD_UNLOCK();
        if (!ok) continue;
        UINT32 lim = (n >= plen) ? n - plen : 0;
        for (UINT32 i = 0; i <= lim; i++) {
            BOOL hit = TRUE;
            for (UINT32 j = 0; j < plen && hit; j++)
                if (mask[j] == 'x' && buf[i+j] != pat[j]) hit = FALSE;
            if (hit) return base + off + i;
        }
    }
#undef _CHUNK
    return 0;
}

static UINT64 s_slBase = 0;
UINT64 ESP_GetSLListBase(void) { return s_slBase; }

void ESP_ScanSchindler(void)
{
    static DWORD s_ms      = 0;
    static BOOL  s_scanned = FALSE;
    DWORD now = GetTickCount();
    if ((now - s_ms) < 5000) return;
    s_ms = now;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) { ESPLOG("[SL] cr3/d2Base not ready"); return; }

    if (!s_scanned) {
        s_scanned = TRUE;
        ESPLOG("[SL] starting AOB scan");
        static const UINT8 pat[]  = {0x48,0x8D,0x2D,0x00,0x00,0x00,0x00,0x8B,0xF2};
        static const UINT8 mask[] = "xxx????xx";
        UINT64 m = _aob_scan(d2Base, 0x6000000ULL, pat, mask, 9, cr3);
        if (!m) { ESPLOG("[SL] AOB not found"); s_scanned = FALSE; return; }
        ESPLOGF("[SL] AOB hit at 0x%I64X", m);
        UINT64 arrVA = _rip_resolve(m, 3, 7, cr3);
        BYOVD_LOCK();
        BYOVD_ReadVA_NoCache(cr3, arrVA + 0x8, &s_slBase, 8);
        BYOVD_UNLOCK();
        ESPLOGF("[SL] arrVA=0x%I64X slBase=0x%I64X", arrVA, s_slBase);
    }
    if (!s_slBase || s_slBase < 0x10000ULL) {
        ESPLOG("[SL] base invalid — will retry");
        s_scanned = FALSE;
    }
}

/* ── Cached matrices: updated by _MatUpdateThread ──────────────────────── */
static volatile LONG  s_matLock  = 0;
static float          s_cView[16];
static float          s_cProj[16];
static BOOL           s_matValid = FALSE;

static void _ml(void)  { while (InterlockedCompareExchange(&s_matLock, 1, 0)) {} }
static void _mu(void)  { InterlockedExchange(&s_matLock, 0); }

BOOL ESP_GetCachedMatrices(float view[16], float proj[16])
{
    _ml();
    BOOL ok = s_matValid;
    if (ok) { memcpy(view, s_cView, 64); memcpy(proj, s_cProj, 64); }
    _mu();
    return ok;
}

static volatile LONG s_upRunning  = 0;
static volatile LONG s_upStop     = 0;
static HANDLE        s_upThread   = NULL;

static DWORD WINAPI _MatUpdateThread(LPVOID p)
{
    (void)p;
    /* NORMAL priority: matrix reads (2×64 bytes, 2 BYOVD IOCTLs) are cheap
     * but freshness is critical — camera rotates every rendered frame and
     * a stale view matrix causes W2S errors visible to the aimbot.          */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    ESPLOG("[MAT] update thread started");

    DWORD lastInitTry    = 0;  /* throttle ESP_Init    (keys+datum scan) */
    DWORD lastResolveTry = 0;  /* throttle ESP_ResolveMatrices (AOB scan)*/
    DWORD lastSLTry      = 0;  /* throttle ESP_ScanSchindler             */

    while (InterlockedCompareExchange(&s_upStop, 0, 0) == 0) {
        DWORD now = GetTickCount();

        /* Step 1: resolve decryption keys (runs once, retries on fail) */
        if (!g_EspState.keys_valid && (now - lastInitTry) >= 1000) {
            lastInitTry = now;
            ESPLOG("[MAT] calling Keys_Init (keys not ready)");
            Keys_Init();
        }

        /* Step 1.5: resolve visuals/matrices/players if not ready */
        if (g_EspState.keys_valid && (!g_EspState.datum_valid || !g_EspState.tl_valid) && (now - lastInitTry) >= 1000) {
            lastInitTry = now;
            ESPLOGF("[MAT] calling ESP_Init: keys_valid=%d datum_valid=%d tl_valid=%d",
                    g_EspState.keys_valid, g_EspState.datum_valid, g_EspState.tl_valid);
            ESP_Init();
        }

        /* Step 2: resolve view/proj matrix VAs (runs once, retries if game reloads) */
        {
            BOOL matValid;
            _ml(); matValid = s_matValid; _mu();
            if (!matValid && (now - lastResolveTry) >= 500) {
                lastResolveTry = now;
                BOOL ok = ESP_ResolveMatrices();
                ESPLOGF("[MAT] ESP_ResolveMatrices returned %d (matrices_valid=%d view_mat_va=0x%I64X)",
                        ok, g_EspState.matrices_valid, g_EspState.view_mat_va);
            }
        }

        /* Step 3: Schindler scan for SL-based positions */
        if ((now - lastSLTry) >= 5000) {
            lastSLTry = now;
            ESP_ScanSchindler();
        }

        if (g_EspState.matrices_valid) {
            static DWORD s_firstFailTime = 0;
            float v[16], pr[16];
            if (ESP_ReadMatrices(v, pr)) {
                s_firstFailTime = 0;
                _ml();
                if (!s_matValid) {
                    ESPLOGF("[MAT] matrices cache filled first time. View[12..14]: %.2f, %.2f, %.2f",
                            v[12], v[13], v[14]);
                }
                memcpy(s_cView, v, 64);
                memcpy(s_cProj, pr, 64);
                s_matValid = TRUE;
                _mu();
            } else {
                if (s_firstFailTime == 0) s_firstFailTime = now;
                if (now - s_firstFailTime >= 500) {
                    static DWORD lastMatFailLog = 0;
                    if (now - lastMatFailLog >= 5000) {
                        lastMatFailLog = now;
                        ESPLOGF("[MAT] ESP_ReadMatrices failed consecutively for 500ms (view_mat_va=0x%I64X) — invalidating cache", g_EspState.view_mat_va);
                    }
                    _ml(); s_matValid = FALSE; _mu();
                }
            }
        }

        /* Step 5: Matchmaking scan (only run when UI feature is active) */
        if (Overlay_GetMatchmakingActive()) {
            Matchmaking_Scan();
        }

        /* 7ms = ~143Hz matrix refresh */
        Sleep(7);
    }

    ESPLOG("[MAT] update thread exiting");
    InterlockedExchange(&s_upRunning, 0);
    InterlockedExchange(&s_upStop,    0);
    return 0;
}

void ESP_StartUpdateThread(void)
{
    if (InterlockedCompareExchange(&s_upRunning, 1, 0) != 0) return;
    InterlockedExchange(&s_upStop, 0);
    ESPLOG("[MAT] ESP_StartUpdateThread: creating thread");
    /* Raise timer resolution once here for all ESP background threads.
     * skeleton.c and esp_overlay.cpp both depend on Sleep(4) accuracy.
     * A single timeBeginPeriod(1) call covers all of them — calling it
     * per-thread would increment the global OS ref-count redundantly and
     * is harder to pair with a matching timeEndPeriod in ESP_StopUpdateThread. */
    timeBeginPeriod(1);
    HANDLE h = CreateThread(NULL, 0, _MatUpdateThread, NULL, 0, NULL);
    if (!h) {
        ESPLOGF("[MAT] CreateThread failed err=%lu", GetLastError());
        InterlockedExchange(&s_upRunning, 0);
        timeEndPeriod(1);
        return;
    }
    s_upThread = h;
}

void ESP_StopUpdateThread(void)
{
    if (!s_upThread) return;
    ESPLOG("[MAT] ESP_StopUpdateThread: signalling stop");
    InterlockedExchange(&s_upStop, 1);
    WaitForSingleObject(s_upThread, 2000);
    CloseHandle(s_upThread);
    s_upThread = NULL;
    _ml(); s_matValid = FALSE; _mu();
    timeEndPeriod(1);
    ESPLOG("[MAT] ESP_StopUpdateThread: done");
}

/* ── Ref-counted update thread lifecycle ──────────────────────────────────── *
 * Multiple callers (Fly, EspOverlay) each Acquire on start and Release on    *
 * stop. The background thread runs as long as refcount > 0.                  */
static volatile LONG s_upRefCount = 0;

void ESP_AcquireUpdateThread(void)
{
    if (InterlockedIncrement(&s_upRefCount) == 1)
        ESP_StartUpdateThread();
}

void ESP_ReleaseUpdateThread(void)
{
    if (InterlockedDecrement(&s_upRefCount) == 0)
        ESP_StopUpdateThread();
}

static UINT32 s_k1 = 0, s_k2 = 0, s_k3 = 0, s_k4 = 0;

/* ── Disk fallback: scan D2 .text in the PE file on disk ──────────────────
 * BYOVD reads physical frames directly. A page with Present=0 (cold/unexecuted
 * code) is invisible to BYOVD. The disk file always has every byte regardless
 * of physical paging state. pattern/mask here are PLAINTEXT (not encrypted). */
/* Helper defined in byovd.c but we can do a local debug print or decryption check if needed. */
extern void decrypt_aob_debug(const UINT8 *src, UINT8 *dst, int len);

BOOL Keys_Init(void)
{
    static BOOL s_keysInitDone = FALSE;
    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2base = GetDestiny2Base();

    static DWORD lastLogTick = 0;
    DWORD nowTick = GetTickCount();
    if (nowTick - lastLogTick >= 2000) {
        lastLogTick = nowTick;
        ESPLOGF("[KEYS_DBG] Keys_Init: cr3=0x%I64X d2base=0x%I64X s_keysInitDone=%d", cr3, d2base, (int)s_keysInitDone);
    }

    if (!cr3 || !d2base) return FALSE;

    if (s_keysInitDone) {
        g_EspState.key1 = s_k1;
        g_EspState.key2 = s_k2;
        g_EspState.key3 = s_k3;
        g_EspState.key4 = s_k4;
        g_EspState.keys_valid = TRUE;
        return TRUE;
    }

    /* Try dynamic scan first */
    UINT32 dk1 = 0, dk2 = 0, dk3 = 0, dk4 = 0;
    BYOVD_LOCK();
    UINT64 m1 = BYOVD_ScanPatternText(cr3, d2base, k1_pat, k1_msk, 14);
    UINT64 m2 = BYOVD_ScanPatternText(cr3, d2base, k2_pat, k2_msk, 8);
    UINT64 m3 = BYOVD_ScanPatternText(cr3, d2base, k3_pat, k3_msk, 10);
    UINT64 m4 = BYOVD_ScanPatternText(cr3, d2base, k4_pat, k4_msk, 8);

    UINT64 fn1 = 0, fn2 = 0, fn3 = 0, fn4 = 0;
    if (m1) { INT32 rel=0; BYOVD_ReadVA(cr3, m1+1, &rel, 4); fn1 = m1 + 5 + (INT64)rel; }
    if (m2) { INT32 rel=0; BYOVD_ReadVA(cr3, m2+1, &rel, 4); fn2 = m2 + 5 + (INT64)rel; }
    if (m3) { INT32 rel=0; BYOVD_ReadVA(cr3, m3+1, &rel, 4); fn3 = m3 + 5 + (INT64)rel; }
    if (m4) { INT32 rel=0; BYOVD_ReadVA(cr3, m4+1, &rel, 4); fn4 = m4 + 5 + (INT64)rel; }

    dk1 = Esp_GetKeyFromFunction(cr3, fn1);
    dk2 = Esp_GetKeyFromFunction(cr3, fn2);
    dk3 = Esp_GetKeyFromFunction(cr3, fn3);
    dk4 = Esp_GetKeyFromFunction(cr3, fn4);
    BYOVD_UNLOCK();

    /* Current working keys for this Destiny 2 build, obfuscated via XOR */
    UINT32 hc_k1 = (UINT32)(0x7689AC92 ^ 0x6F4E8391); // 0x19C72F03
    UINT32 hc_k2 = (UINT32)(0x76686831 ^ 0x12A9E5B7); // 0x64C18D86
    UINT32 hc_k3 = (UINT32)(0x26353B22 ^ 0x5B8D12A9); // 0x7DB8298B
    UINT32 hc_k4 = (UINT32)(0x17CBECC1 ^ 0x4A1E9F23); // 0x5DD573E2

    char _logmsg[256];
    wsprintfA(_logmsg, "[KEYS_DIAG] Dynamic keys: dk1=0x%X dk2=0x%X dk3=0x%X dk4=0x%X", dk1, dk2, dk3, dk4);
    WriteEspLog(_logmsg);
    wsprintfA(_logmsg, "[KEYS_DIAG] Hardcoded keys: hc_k1=0x%X hc_k2=0x%X hc_k3=0x%X hc_k4=0x%X", hc_k1, hc_k2, hc_k3, hc_k4);
    WriteEspLog(_logmsg);

    if (dk1 && dk2 && dk3 && dk4) {
        s_k1 = dk1; s_k2 = dk2; s_k3 = dk3; s_k4 = dk4;
        WriteEspLog("[KEYS] Using dynamically scanned keys");
    } else {
        s_k1 = hc_k1; s_k2 = hc_k2; s_k3 = hc_k3; s_k4 = hc_k4;
        WriteEspLog("[KEYS] Dynamic scan failed, falling back to hardcoded keys");
    }

    g_EspState.key1 = s_k1;
    g_EspState.key2 = s_k2;
    g_EspState.key3 = s_k3;
    g_EspState.key4 = s_k4;
    g_EspState.keys_valid = TRUE;
    s_keysInitDone = TRUE;
    return TRUE;
}

