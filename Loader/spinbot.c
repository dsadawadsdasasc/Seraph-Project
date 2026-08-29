/* spinbot.c — Destiny 2 view-direction randomizer ("Spinbot")
 *
 * Strategy (mirrors the Cheat Engine reference script):
 *   1. AOB scan for the view-direction write site:
 *        0F 11 02  — movups [rdx], xmm0
 *        C3        — ret
 *        ...
 *      This is the instruction that writes the local player's aim direction
 *      (a unit-vector float3) into game memory each frame.
 *
 *   2. A code cave is installed via LazyHook.  The cave does:
 *        — executes the original stolen bytes (movups [rdx],xmm0)
 *        — stores rdx into a shared QWORD (s_capturedAddr) so the randomizer
 *          thread knows where the float3 lives
 *
 *   3. A background thread (SpinBot_Thread) runs at ~1 ms intervals:
 *        — validates the captured address (pointer sanity + float range checks)
 *        — writes 3 pseudo-random floats in (-1.0, 1.0) \ {0, ±1} to that
 *          address via BYOVD_WriteVA (kernel-level write, stealth-safe)
 *        — if player is dead (all-zero coords at COORDS_BASE_ADDR) it clears
 *          the captured address
 *
 * Hook site: 4 bytes stolen (movups [rdx],xmm0 = 3 bytes + ret = 1 byte)
 * We steal 5 bytes minimum for a rel32 JMP, so we take the first 5 bytes of
 * the pattern: 0F 11 02 C3 48  — the 48 is the start of "48 8D 64 24 08"
 * (lea rsp,[rsp+8]), which is position-independent; we re-emit it in the cave.
 *
 * Cave shellcode (injected BEFORE the stolen bytes):
 *   push rax
 *   mov  rax, <s_capturedAddr VA in loader address space — NOT used>
 *   -- Instead we store rdx using a BYOVD-free trick: we write it to a
 *      shared volatile UINT64 that is accessible from the loader thread
 *      because the hook cave runs INSIDE destiny2.exe's address space at the
 *      game's CR3. The loader thread has mapped the same VA only if we use
 *      a kernel write target.  We therefore store the captured VA in a small
 *      alloc inside destiny2.exe that we allocate via BYOVD_AllocVA, and the
 *      thread reads it back via BYOVD_ReadVA.
 *
 * NOTE: The cave shellcode stores rdx into [s_storeVA] each call.
 *       The thread polls s_storeVA every ~1 ms via BYOVD_ReadVA.
 */

#include "ThemidaSDK.h"
#include "spinbot.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include "syscalls.h"   /* SeraphCreateThread, SeraphSleep, SysNtClose */
#include <windows.h>
#include <math.h>
#include <string.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

/* AOB: movups [rdx],xmm0 (3) + ret (1) + lea rsp,[rsp+8] partial (1) = 5 stolen */
#define SB_STOLEN_LEN   5
#define SB_CAVE_NEED    128

/* Player alive coords offset (same as the CE Lua script) */
#define SB_COORDS_OFFSET  0x32F3AC0ULL

/* Spin speed: ms between randomization writes */
#define SB_TICK_MS        1

/* Float bounds for valid aim direction component */
#define SB_FLOAT_MIN   (-0.99f)
#define SB_FLOAT_MAX    (0.99f)

/* ── State ────────────────────────────────────────────────────────────────── */

static UINT64         s_preScanVA   = 0;
static UINT64         s_hookVA      = 0;   /* patch site VA inside d2     */
static UINT64         s_caveVA      = 0;   /* code cave VA                */
static UINT64         s_storeVA     = 0;   /* alloc'd slot: holds captured rdx */
static int            s_hookId      = -1;
static BOOL           s_enabled     = FALSE;

static volatile LONG  s_threadStop  = 0;
static HANDLE         s_thread      = NULL;

/* ── Tiny LCG PRNG (no CRT rand — stealth) ──────────────────────────────── */

static UINT32 s_seed = 0;

static void _SeedFromTick(void)
{
    s_seed = (UINT32)(GetTickCount() ^ (GetTickCount() * 0x9E3779B9UL));
    if (!s_seed) s_seed = 0xDEADBEEF;
}

static float _RandFloat(void)
{
    /* Xorshift32 */
    UINT32 x = s_seed;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    s_seed = x;
    /* Map to (-1, 1) */
    float f = (float)(x & 0x7FFFFFFF) / (float)0x7FFFFFFF * 2.0f - 1.0f;
    return f;
}

/* Produce a float in (SB_FLOAT_MIN, SB_FLOAT_MAX) \ {0, ±0.9xx...} that
 * won't be filtered by the CE script's validVal() check. */
static float _RandAimComponent(void)
{
    float v;
    int guard = 0;
    do {
        v = _RandFloat();
        /* reject exactly 0, ±1 and out-of-range */
        if (v < SB_FLOAT_MIN || v > SB_FLOAT_MAX) v = 0.5f;
        if (v == 0.0f) v = 0.01f;
        guard++;
    } while ((v == 0.0f || v >= 1.0f || v <= -1.0f) && guard < 8);
    return v;
}

/* ── Player-alive check ───────────────────────────────────────────────────── */

static BOOL _IsPlayerAlive(UINT64 cr3, UINT64 d2Base)
{
    if (!cr3 || !d2Base) return FALSE;
    UINT64 coordsVA = d2Base + SB_COORDS_OFFSET;
    float xyz[3] = {0};
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, coordsVA, xyz, sizeof(xyz));
    BYOVD_UNLOCK();
    if (!ok) return FALSE;
    return !(xyz[0] == 0.0f && xyz[1] == 0.0f && xyz[2] == 0.0f);
}

/* ── Validate captured address ───────────────────────────────────────────── */

static BOOL _ValidAddr(UINT64 addr)
{
    if (!addr) return FALSE;
    if (addr < 0x10000ULL)            return FALSE;
    if (addr >= 0x7FFFFFFF0000ULL)    return FALSE;
    if (addr >= 0x100000000ULL)       return FALSE; /* must be 32-bit low for sane D2 float ptr */
    return TRUE;
}

/* ── Randomizer thread ────────────────────────────────────────────────────── */

static DWORD WINAPI SpinBot_Thread(LPVOID lpParam)
{
    (void)lpParam;
    _SeedFromTick();

    while (!InterlockedCompareExchange(&s_threadStop, 0, 0))
    {
        if (!s_enabled || !s_storeVA) {
            SeraphSleep(10);
            continue;
        }

        UINT64 cr3    = GetDestiny2CR3();
        UINT64 d2Base = GetDestiny2Base();
        if (!cr3 || !d2Base) {
            SeraphSleep(10);
            continue;
        }

        /* Read captured rdx from the store slot */
        UINT64 targetVA = 0;
        BYOVD_LOCK();
        BOOL rdOk = BYOVD_ReadVA(cr3, s_storeVA, &targetVA, 8);
        BYOVD_UNLOCK();

        if (!rdOk || !_ValidAddr(targetVA)) {
            SeraphSleep(SB_TICK_MS);
            continue;
        }

        /* If player is dead, clear the captured address */
        if (!_IsPlayerAlive(cr3, d2Base)) {
            UINT64 zero = 0;
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_storeVA, &zero, 8);
            BYOVD_UNLOCK();
            SeraphSleep(50);
            continue;
        }

        /* Validate the floats at targetVA before writing */
        float cur[3] = {0};
        BYOVD_LOCK();
        BOOL readOk = BYOVD_ReadVA(cr3, targetVA, cur, sizeof(cur));
        BYOVD_UNLOCK();

        if (!readOk) {
            SeraphSleep(SB_TICK_MS);
            continue;
        }

        /* Sanity check: if all zero the address is stale */
        if (cur[0] == 0.0f && cur[1] == 0.0f && cur[2] == 0.0f) {
            UINT64 zero = 0;
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_storeVA, &zero, 8);
            BYOVD_UNLOCK();
            SeraphSleep(SB_TICK_MS);
            continue;
        }

        /* Write 3 randomized components */
        float spin[3];
        spin[0] = _RandAimComponent();
        spin[1] = _RandAimComponent();
        spin[2] = _RandAimComponent();

        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, targetVA,     &spin[0], 4);
        BYOVD_WriteVA(cr3, targetVA + 4, &spin[1], 4);
        BYOVD_WriteVA(cr3, targetVA + 8, &spin[2], 4);
        BYOVD_UNLOCK();

        SeraphSleep(SB_TICK_MS);
    }

    return 0;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void SpinBot_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL SpinBot_IsReady(void)  { return s_hookVA != 0 && s_caveVA != 0 && s_storeVA != 0; }
BOOL SpinBot_IsEnabled(void){ return s_enabled; }

/* ── OnAttach ─────────────────────────────────────────────────────────────── */

#pragma optimize("", off)
void SpinBot_OnAttach(void)
{
    MUTATE_START
    s_hookVA   = 0;
    s_caveVA   = 0;
    s_storeVA  = 0;
    s_hookId   = -1;
    s_enabled  = FALSE;
    InterlockedExchange(&s_threadStop, 0);

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _sb_end;

    /* ── Resolve hook VA ──────────────────────────────────────────────────── *
     * AOB: 0F 11 02 C3 48 8D 64 24 08 FF 64 24 F8 48
     * Hardcoded offset (same approach as silent_aim / thirdperson).
     * If pre-scan provided a VA, use it; otherwise fall back to hardcoded.   */
    UINT64 matchVA = s_preScanVA;
    s_preScanVA = 0;
    if (!matchVA) {
        /* Hardcoded relative offset — update when game patches */
        matchVA = d2Base + 0x322A6EULL;
    }
    s_hookVA = matchVA;

    /* ── Find code cave ───────────────────────────────────────────────────── *
     * FindFirst parses the cave candidates fast and checks for reservations.
     * We don't need a location-specific cave (FindNear) since a standard relative
     * jump covers the target offset range.                                    */
    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindFirst(cr3, d2Base, SB_CAVE_NEED);
    BYOVD_UNLOCK();
    if (!s_caveVA) {
        DEBUG_FLY("SpinBot_OnAttach: cave not found");
        s_hookVA = 0;
        goto _sb_end;
    }
    CaveFinder_Reserve(s_caveVA, SB_CAVE_NEED);

    /* ── Allocate storage slot (8 bytes) inside the cave area ────────────── *
     * We carve the last 8 bytes of the cave as the rdx store slot.           */
    s_storeVA = s_caveVA + SB_CAVE_NEED - 8;
    /* Zero it */
    {
        UINT64 zero = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_storeVA, &zero, 8);
        BYOVD_UNLOCK();
    }

    DEBUG_FLY("SpinBot_OnAttach: hookVA=0x%I64X caveVA=0x%I64X storeVA=0x%I64X",
              s_hookVA, s_caveVA, s_storeVA);

    /* ── Start randomizer thread ─────────────────────────────────────────── */
    if (!s_thread) {
        s_thread = SeraphCreateThread(SpinBot_Thread, NULL);
        if (!s_thread) {
            DEBUG_FLY("SpinBot_OnAttach: FATAL -- thread creation failed");
        }
    }

_sb_end:
    MUTATE_END
}
#pragma optimize("", on)

/* ── OnDetach ─────────────────────────────────────────────────────────────── */

#pragma optimize("", off)
void SpinBot_OnDetach(void)
{
    MUTATE_START
    /* Stop thread */
    InterlockedExchange(&s_threadStop, 1);
    if (s_thread) {
        WaitForSingleObject(s_thread, 2000);
        SysNtClose(s_thread);
        s_thread = NULL;
    }
    InterlockedExchange(&s_threadStop, 0);

    /* Remove hook if installed */
    if (s_hookId >= 0) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
    }

    s_hookVA  = 0;
    s_caveVA  = 0;
    s_storeVA = 0;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

/* ── SetEnabled ───────────────────────────────────────────────────────────── */

void SpinBot_SetEnabled(BOOL state)
{
    if (!SpinBot_IsReady()) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    BYOVD_LOCK();
    if (state && s_hookId < 0) {
        /* Shellcode: store rdx (aim-dir float3 pointer) into s_storeVA.
         *
         * Layout (position-independent, RIP-relative store):
         *   push  rax                    ; 50
         *   push  rcx                    ; 51
         *   lea   rcx, [rip + disp]      ; 48 8D 0D <disp32>  — point to storeVA slot
         *   mov   [rcx], rdx             ; 48 89 11
         *   pop   rcx                    ; 59
         *   pop   rax                    ; 58
         *
         * disp32 is relative to (rip after the lea) → storeVA - (caveVA + sc_len + 5 + 5 + 4)
         * We compute it at install time.
         *
         * sc total = 1+1+7+3+1+1 = 14 bytes
         * After these 14 bytes come the stolen 5 bytes + 5-byte JMP back = 24 bytes total.
         * caveVA layout:
         *   [0..13]  shellcode
         *   [14..18] stolen bytes (5)
         *   [19..23] E9 rel32 JMP back
         *   ...
         *   [120..127] storeVA data (8 bytes) ← s_storeVA = caveVA + 120
         *
         * RIP after lea = caveVA + 0 + 1 + 1 + 7 = caveVA + 9
         * target = s_storeVA = caveVA + 120
         * disp = 120 - 9 = 111  (0x6F)
         */
        UINT8 sc[14];
        int p = 0;
        sc[p++] = 0x50;                          /* push rax */
        sc[p++] = 0x51;                          /* push rcx */
        /* lea rcx, [rip + disp32] */
        sc[p++] = 0x48; sc[p++] = 0x8D; sc[p++] = 0x0D;
        INT32 disp = (INT32)(s_storeVA - (s_caveVA + (UINT64)p + 4));
        *(INT32*)(sc + p) = disp; p += 4;
        /* mov [rcx], rdx */
        sc[p++] = 0x48; sc[p++] = 0x89; sc[p++] = 0x11;
        sc[p++] = 0x59;                          /* pop rcx */
        sc[p++] = 0x58;                          /* pop rax */

        s_hookId = LazyHook_Install(cr3, s_hookVA, SB_STOLEN_LEN,
                                    sc, (UINT32)p, s_caveVA);
        DEBUG_FLY("SpinBot_SetEnabled(TRUE): hookId=%d", s_hookId);
    } else if (!state && s_hookId >= 0) {
        LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
        /* Clear stored address */
        if (s_storeVA) {
            UINT64 zero = 0;
            BYOVD_WriteVA(cr3, s_storeVA, &zero, 8);
        }
        DEBUG_FLY("SpinBot_SetEnabled(FALSE): hook removed");
    }
    BYOVD_UNLOCK();

    s_enabled = state;
}
