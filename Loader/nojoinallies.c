/* nojoinallies.c — Anti-Join port of the CE "antiJoin" script.
 *
 * Original CE AOB & semantics:
 *   aobscanmodule(antiJoin,destiny2.exe,48 8B 00 48 01 47 30)   // unique
 *     48 8B 00          mov rax, [rax]            (load joining-ally handle)
 *     48 01 47 30       add [rdi+0x30], rax       (ACCUMULATE into slot)
 *
 * The CE script replaces these 7 bytes with `jmp newmem; nop; nop`.  newmem
 * uses an arm-flag so on the FIRST execution it zeros [rdi+0x30] and clears
 * the flag, then on every subsequent execution it just falls through (the
 * original add is never re-executed → accumulator stays 0).
 *
 * Equivalent in-place patch (no cave required): replace the 7-byte AOB
 * span with `xor rax,rax; mov [rdi+0x30], rax`.  Every call now writes 0,
 * which is functionally stronger than the CE arm-flag approach (it would
 * even survive if the slot got re-populated by some other code path).
 *
 * Patch (7 bytes, fits exactly in the AOB span):
 *     48 31 C0          xor rax, rax
 *     48 89 47 30       mov [rdi+0x30], rax
 */

#define SERAPH_DISABLE_MUTATE
#include "ThemidaSDK.h"
#include "nojoinallies.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "attach.h"
#include "d2_patches.h"
#include "debug.h"
#include <string.h>

#define NJA_AOB_LEN     7
#define NJA_PATCH_LEN   7

static int    s_njaPatchId = -1;
static UINT64 s_preScanVA  = 0;

void NoJoinAllies_SetPreScanResult(UINT64 matchVA) { s_preScanVA = matchVA; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void NoJoinAllies_OnAttach(void)
{
    MUTATE_START
    s_njaPatchId = -1;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _nja_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        DEBUG_PATCH("NoJoinAllies: AOB not found");
        goto _nja_end;
    }



    /* In-place forced-zero store (replaces `mov rax,[rax]; add [rdi+30],rax`
     * with `xor rax,rax; mov [rdi+30],rax`).  7 bytes — same width. */
    static const UINT8 zeroStore[NJA_PATCH_LEN] = {
        0x48, 0x31, 0xC0,             /* xor rax, rax       */
        0x48, 0x89, 0x47, 0x30        /* mov [rdi+30], rax  */
    };
    int id = Patch_Register("No Joining Allies", matchVA, zeroStore, NJA_PATCH_LEN);
    if (id < 0) {
        DEBUG_PATCH("NoJoinAllies: Patch_Register failed");
        goto _nja_end;
    }
    s_njaPatchId = id;
    D2Patches_SetExternalTabForId(id, 1);   /* MISC tab — same as NoTurnBack */
    DEBUG_PATCH("NoJoinAllies: id=%d match=0x%I64X", id, matchVA);

_nja_end:
    MUTATE_END
}
#pragma optimize("", on)

void NoJoinAllies_OnDetach(void)
{
    s_njaPatchId = -1;
}

int NoJoinAllies_GetPatchId(void) { return s_njaPatchId; }

/* No observer hook needed — the in-place patch already re-zeros [rdi+0x30]
 * on every call.  Kept as no-op for ABI compatibility with gui_core.cpp. */
void NoJoinAllies_TriggerOneShotZero(void) { /* no-op */ }

#if 1
/* =========================================================================
   PREVIOUS VERSION (SIMPLIFIED): Vanish version.
   This version is what we were using until now. It is a direct 6-NOP patch
   targeting a different AOB.
   ========================================================================= */
#if 0
/*
#define NJA_AOB_LEN_SIMPLIFIED   6
#define NJA_PATCH_LEN_SIMPLIFIED 6
const UINT8 k_nja_pat_simplified[]  = { 0x48, 0x01, 0x47, 0x30, 0xEB, 0x64 };
const UINT8 k_nja_mask_simplified[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
*/
void NoJoinAllies_OnAttach_Simplified(void)
{
    s_njaPatchId = -1;
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_nja_pat_simplified, k_nja_mask_simplified, NJA_AOB_LEN_SIMPLIFIED);
        BYOVD_UNLOCK();
    }
    if (!matchVA) return;

    static const UINT8 nops[NJA_PATCH_LEN_SIMPLIFIED] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    };
    int id = Patch_Register("No Joining Allies", matchVA, nops, NJA_PATCH_LEN_SIMPLIFIED);
    if (id < 0) return;
    s_njaPatchId = id;
}
#endif
#endif
