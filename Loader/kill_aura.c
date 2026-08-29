
/* kill_aura.c — Direct JMP + cave approach.
 *
 * CE script:
 *   aobscanregion(killaura_base, 7FF000000000, 7FFFFFFFFFFF,
 *                 33 C2 E9 ?? ?? ?? ?? F3 0F 10 41 20 32 C0)
 *   define(alvo, killaura_base+7)
 *   alloc(newmem, $1000, alvo)
 *   newmem:
 *     mov [rcx+20], (float)1000
 *     movss xmm0, [rcx+20]
 *     jmp return
 *   alvo:
 *     jmp newmem
 *   return:
 *
 * AOB: 33 C2 E9 ?? ?? ?? ?? F3 0F 10 41 20 32 C0 (13 bytes)
 * Hook target = matchVA + 7 (movss xmm0,[rcx+0x20], 5 bytes)
 * Stolen = 5 bytes
 *
 * Cave mailboxes:
 *   +0x00  float kill_value  (live-updated by SetMultiplier)
 *
 * Shellcode:
 *   mov eax, [rip+mailbox]   8B 05 disp32
 *   mov [rcx+0x20], eax      89 41 20
 *   movss xmm0, [rcx+0x20]  F3 0F 10 41 20
 *   jmp return               E9 disp32
 * Total: ~22 bytes
 */

#include "ThemidaSDK.h"
#include "kill_aura.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "patch.h"
#include "cave_finder.h"
#include "debug.h"
#include <string.h>

/* ── AOB ───────────────────────────────────────────────────────────────────── */
#define KA_AOB_LEN       13
#define KA_AOB_OFF        7   /* hook target = matchVA + 7 (movss xmm0,[rcx+0x20]) */
#define KA_STOLEN_LEN     5   /* bytes stolen: F3 0F 10 41 20 */
#define KA_CAVE_NEED     64   /* data(8) + shellcode(~22) is safe */

static const UINT8 KA_EXPECT[5] = {0xF3, 0x0F, 0x10, 0x41, 0x20};








static UINT64  s_preScanVA  = 0;
static UINT64  s_caveVA     = 0;  /* code cave VA for mailbox + shellcode */
static UINT64  s_origVA     = 0;  /* VA of the hook target (stolen instruction) */
static UINT8   s_origBytes[KA_STOLEN_LEN]; /* saved original bytes for restore */
static BOOL    s_patched    = FALSE;
static int     s_kaValue    = 100;
static BOOL    s_enabled    = FALSE;

/* Scale factor: slider 1-100 → 10.0-1000.0f in-game field */
#define KA_VALUE_SCALE 10.0f

void KillAura_SetPreScanResult(UINT64 va) { s_preScanVA = va; }


#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void KillAura_OnAttach(void)
{
    MUTATE_START
    s_caveVA = 0; s_origVA = 0; s_patched = FALSE;
    s_kaValue = 100; s_enabled = FALSE;
    memset(s_origBytes, 0, sizeof(s_origBytes));

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _ka_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) goto _ka_end;
    s_origVA = matchVA + KA_AOB_OFF;



    /* Validate target bytes */
    UINT8 tgt[5] = {0};
    BYOVD_LOCK(); BYOVD_ReadVA(cr3, s_origVA, tgt, 5); BYOVD_UNLOCK();
    if (memcmp(tgt, KA_EXPECT, 5) != 0) {
        DEBUG_PATCH("KillAura: target mismatch at 0x%I64X", s_origVA);
        s_origVA = 0;
        goto _ka_end;
    }

    /* Save original bytes */
    memcpy(s_origBytes, KA_EXPECT, KA_STOLEN_LEN);

    /* Find code cave */
    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindFirst(cr3, d2Base, KA_CAVE_NEED);
    BYOVD_UNLOCK();
    if (!s_caveVA) {
        DEBUG_PATCH("KillAura: no cave");
        s_origVA = 0;
        goto _ka_end;
    }

    DEBUG_PATCH("KillAura: OK match=0x%I64X cave=0x%I64X", matchVA, s_caveVA);

_ka_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL KillAura_IsReady(void) { return s_origVA != 0 && s_caveVA != 0; }

void KillAura_SetMultiplier(int value)
{
    s_kaValue = value;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    float fval = (float)s_kaValue * KA_VALUE_SCALE;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_caveVA, &fval, 4);
    BYOVD_UNLOCK();
}

int KillAura_GetMultiplier(void) { return s_kaValue; }

/* ── Shellcode builder (writes into cave) ────────────────────────────────────
 * Layout:
 *   +0x00  float kill_value     (read by shellcode via RIP-relative)
 *   +0x08  shellcode             (built dynamically)
 *
 * Shellcode:
 *   mov eax, [rip+kill_value]   8B 05 disp32       (6)
 *   mov [rcx+0x20], eax         89 41 20           (3)
 *   movss xmm0, [rcx+0x20]     F3 0F 10 41 20     (5)
 *   jmp return                  E9 disp32          (5)
 *   = 19 bytes                                                                 */
static int BuildShellcode(UINT8 *buf, UINT64 caveBase, UINT64 returnVA)
{
    UINT64 scBase = caveBase + 0x08;
    UINT64 mailVA = caveBase + 0x00; /* float kill_value */
    int p = 0;

    /* mov eax, [rip+mailVA] */
    {
        UINT64 ip = scBase + p;
        INT32 disp = (INT32)((INT64)mailVA - (INT64)(ip + 6));
        buf[p++] = 0x8B; buf[p++] = 0x05;
        *(INT32*)(buf + p) = disp; p += 4;
    }

    /* mov [rcx+0x20], eax */
    buf[p++] = 0x89; buf[p++] = 0x41; buf[p++] = 0x20;

    /* movss xmm0, [rcx+0x20] */
    buf[p++] = 0xF3; buf[p++] = 0x0F; buf[p++] = 0x10; buf[p++] = 0x41; buf[p++] = 0x20;

    /* jmp returnVA */
    {
        UINT64 ip = scBase + p;
        INT32 disp = (INT32)((INT64)returnVA - (INT64)(ip + 5));
        buf[p++] = 0xE9;
        *(INT32*)(buf + p) = disp; p += 4;
    }

    return p;
}

void KillAura_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    s_enabled = state;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !KillAura_IsReady()) { s_enabled = FALSE; return; }

    if (state) {
        if (s_patched) return;

        /* Build and write shellcode to cave */
        UINT8 buf[KA_CAVE_NEED];
        memset(buf, 0, sizeof(buf));

        /* Pre-write the default kill_value */
        *(float*)(buf + 0x00) = (float)s_kaValue * KA_VALUE_SCALE;

        int scLen = BuildShellcode(buf, s_caveVA, s_origVA + KA_STOLEN_LEN);
        if (scLen <= 0) { s_enabled = FALSE; return; }

        BYOVD_LOCK();
        BOOL ok = BYOVD_WriteVA(cr3, s_caveVA, buf, 0x08 + scLen);
        BYOVD_UNLOCK();
        if (!ok) { s_enabled = FALSE; return; }

        /* Write direct JMP at hook site (E9 rel32 = 5 bytes, exactly replaces stolen) */
        UINT8 patch[5];
        patch[0] = 0xE9;
        INT32 rel = (INT32)((INT64)(s_caveVA + 0x08) - (INT64)(s_origVA + 5));
        *(INT32*)(patch + 1) = rel;

        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_origVA, patch, 5);
        BYOVD_UNLOCK();

        s_patched = TRUE;
        DEBUG_PATCH("KillAura: ENABLED cave=0x%I64X val=%d", s_caveVA, s_kaValue);
    } else {
        if (!s_patched) return;

        /* Zero the kill_value mailbox so any in-flight call writes 0 */
        float zerof = 0.0f;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA, &zerof, 4);
        BYOVD_UNLOCK();

        /* Restore original bytes */
        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_origVA, s_origBytes, KA_STOLEN_LEN);
        BYOVD_UNLOCK();

        s_patched = FALSE;
        DEBUG_PATCH("KillAura: DISABLED");
    }
}

#pragma optimize("", off)
void KillAura_OnDetach(void)
{
    MUTATE_START
    if (s_patched) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA_Fresh(cr3, s_origVA, s_origBytes, KA_STOLEN_LEN);
            BYOVD_UNLOCK();
        }
        s_patched = FALSE;
    }
    s_caveVA = 0; s_origVA = 0;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

