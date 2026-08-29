#include "ThemidaSDK.h"
#include "rapid_fire.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include <string.h>

#include "aob_patterns.h"

#define RF_AOB_LEN      15
#define RF_HOOK_LEN     8    /* 8 bytes: call cave (5) + 3 nops (3), or movss [rsi+0x17CC], xmm0 */
#define RF_CAVE_NEED    32
#define RF_MULT_OFF     0x15

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static BOOL   s_enabled   = FALSE;
static float  s_mult      = 5.0f;  /* default: 5x fire rate */
static UINT8  s_origBytes[RF_HOOK_LEN] = { 0xF3, 0x0F, 0x11, 0x86, 0xCC, 0x17, 0x00, 0x00 };

void RapidFire_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL RapidFire_IsReady(void)               { return s_hookVA != 0; }
BOOL RapidFire_IsEnabled(void)             { return s_enabled; }

#include "xor_strings.h"

#pragma optimize("", off)
void RapidFire_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_caveVA = 0;
    s_enabled = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        matchVA = d2Base + SecureReadStatic(&OBF_OFF_RapidFire);
    }
    if (!matchVA) {
        DEBUG_FLY("RapidFire_OnAttach: AOB match failed");
        goto _end;
    }

    s_hookVA = matchVA;

    BYOVD_LOCK();
    /* Save actual original 8 bytes from game memory */
    BYOVD_ReadVA(cr3, s_hookVA, s_origBytes, RF_HOOK_LEN);

    s_caveVA = CaveFinder_FindNear(cr3, d2Base, RF_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    if (!s_caveVA) {
        DEBUG_FLY("RapidFire_OnAttach: cave not found");
        s_hookVA = 0;
        goto _end;
    }

    /* Build cave payload matching exact logic:
     *   hook:
     *     movss xmm1, [rip + 0x0D]     ; F3 0F 10 0D 0D 00 00 00 (8 bytes -> multiplier @ cave+0x15)
     *     divss xmm0, xmm1             ; F3 0F 5E C1             (4 bytes)
     *     movss [rsi + 0x17CC], xmm0   ; s_origBytes             (8 bytes)
     *     ret                          ; C3                      (1 byte)
     *   multiplier:
     *     dd <float>                   ; 4 bytes float @ cave+0x15
     */
    UINT8 cave[RF_CAVE_NEED];
    memset(cave, 0x90, sizeof(cave));

    /* 0x00: movss xmm1, [rip + 0x0D] */
    cave[0x00] = 0xF3; cave[0x01] = 0x0F; cave[0x02] = 0x10; cave[0x03] = 0x0D;
    *(INT32*)(cave + 0x04) = 0x0D;

    /* 0x08: divss xmm0, xmm1 */
    cave[0x08] = 0xF3; cave[0x09] = 0x0F; cave[0x0A] = 0x5E; cave[0x0B] = 0xC1;

    /* 0x0C: original movss [rsi + 0x17CC], xmm0 */
    memcpy(cave + 0x0C, s_origBytes, RF_HOOK_LEN);

    /* 0x14: ret */
    cave[0x14] = 0xC3;

    /* 0x15: float multiplier */
    *(float*)(cave + RF_MULT_OFF) = s_mult;

    BYOVD_LOCK();
    BOOL ok = BYOVD_WriteVA_Fresh(cr3, s_caveVA, cave, RF_CAVE_NEED);
    BYOVD_UNLOCK();
    if (!ok) {
        DEBUG_FLY("RapidFire_OnAttach: cave write failed");
        s_hookVA = s_caveVA = 0;
        goto _end;
    }

    DEBUG_FLY("RapidFire_OnAttach: ready (hookVA=0x%I64X, cave=0x%I64X)", s_hookVA, s_caveVA);

_end:
    MUTATE_END
}
#pragma optimize("", on)

#pragma optimize("", off)
void RapidFire_OnDetach(void)
{
    MUTATE_START
    if (s_enabled) {
        RapidFire_SetEnabled(FALSE);
    }
    s_hookVA = 0; s_caveVA = 0;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

void RapidFire_SetMultiplier(float mult)
{
    if (mult < 1.0f) mult = 1.0f;
    if (mult > 20.0f) mult = 20.0f;
    s_mult = mult;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    BYOVD_LOCK();
    BYOVD_WriteVA_Fresh(cr3, s_caveVA + RF_MULT_OFF, &s_mult, sizeof(float));
    BYOVD_UNLOCK();
}

void RapidFire_SetEnabled(BOOL state)
{
    s_enabled = state;
    if (!s_caveVA || !s_hookVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    BYOVD_LOCK();
    if (state) {
        /* Write call <s_caveVA> + 3 NOPs to s_hookVA */
        UINT8 patch[RF_HOOK_LEN];
        patch[0] = 0xE8; /* call rel32 */
        INT32 rel = (INT32)((INT64)s_caveVA - (INT64)(s_hookVA + 5));
        *(INT32*)(patch + 1) = rel;
        patch[5] = 0x90; patch[6] = 0x90; patch[7] = 0x90;

        BYOVD_WriteVA_Fresh(cr3, s_hookVA, patch, RF_HOOK_LEN);
        DEBUG_FLY("RapidFire_SetEnabled(TRUE): patched hookVA=0x%I64X", s_hookVA);
    } else {
        /* Restore original 8 bytes */
        BYOVD_WriteVA_Fresh(cr3, s_hookVA, s_origBytes, RF_HOOK_LEN);
        DEBUG_FLY("RapidFire_SetEnabled(FALSE): restored hookVA=0x%I64X", s_hookVA);
    }
    BYOVD_UNLOCK();
}
