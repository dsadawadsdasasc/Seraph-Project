
/* instant_abilities.c — Instant Abilities.
 *
 * AOB (11 bytes, all exact — `// unique` in the CE script):
 *   F3 41 0F 5C C3        subss  xmm0, xmm11        ; cooldown -= dt
 *   0F 2F C6              comiss xmm0, xmm6         ; compare with threshold
 *   73 04                 jae    +4                 ; skip-if-not-ready branch
 *   44                    (REX prefix of NEXT instruction — NOT patched)
 *
 * Patch (10 bytes of 0x90 over subss + comiss + jae): the cooldown timer
 * is no longer decremented, no comparison happens, no skip branch fires.
 * Execution falls straight through to the "ability ready" path every frame.
 *
 * The 0x44 REX prefix is intentionally NOT patched: it belongs to the
 * instruction immediately AFTER the AOB.  Replacing it with 0x90 would
 * change the encoding of that instruction (likely from a high-register
 * variant to a low-register variant) and corrupt state.
 *
 * Toggling is handled by the standard Patch_Apply / Patch_Restore system. */

#include "ThemidaSDK.h"
#include "instant_abilities.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "attach.h"
#include "d2_patches.h"
#include "debug.h"
#include <string.h>

/* ── AOB ────────────────────────────────────────────────────────────────── */






#define IA_AOB_LEN     11
#define IA_PATCH_LEN   5    /* NOP just subss xmm0,xmm11 (5 bytes) — leaves
                             * comiss/jae intact; cooldown stops decrementing,
                             * abilities stay perma-ready.                  */

static int    s_iaPatchId  = -1;
static UINT64 s_preScanVA  = 0;

void InstantAbilities_SetPreScanResult(UINT64 matchVA) { s_preScanVA = matchVA; }

/* ── Public API ──────────────────────────────────────────────────────────── */
#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void InstantAbilities_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("IA: A enter");
    s_iaPatchId = -1;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    {
        char b[160]; wsprintfA(b,"IA: B cr3=0x%I64X base=0x%I64X", cr3, d2Base); WriteLogFile(b);
    }
    if (!cr3 || !d2Base) { WriteLogFile("IA: no cr3/base"); goto _ia_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_ia_pat, k_ia_mask, 11);
        BYOVD_UNLOCK();
    }
    {
        char b[96]; wsprintfA(b,"IA: E matchVA=0x%I64X", matchVA); WriteLogFile(b);
    }
    if (!matchVA) {
        WriteLogFile("IA: AOB not found");
        goto _ia_end;
    }


    /* 5 NOPs over subss xmm0,xmm11 (F3 41 0F 5C C3). */
    static const UINT8 patch[IA_PATCH_LEN] = {
        0x90, 0x90, 0x90, 0x90, 0x90
    };

    WriteLogFile("IA: F Patch_Register START");
    int id = Patch_Register("Instant Abilities", matchVA, patch, IA_PATCH_LEN);
    {
        char b[64]; wsprintfA(b,"IA: G Patch_Register DONE id=%d", id); WriteLogFile(b);
    }
    if (id < 0) {
        WriteLogFile("IA: Patch_Register failed");
        goto _ia_end;
    }
    s_iaPatchId = id;
    D2Patches_SetExternalTabForId(id, 10);   /* ABILITIES tab */
    WriteLogFile("IA: I SetExternalTabForId DONE");

_ia_end:
    WriteLogFile("IA: Z exit");
    MUTATE_END
}
#pragma optimize("", on)

void InstantAbilities_OnDetach(void)
{
    s_iaPatchId = -1;
}

void InstantAbilities_SetEnabled(BOOL en)
{
    if (s_iaPatchId < 0) return;
    if (en)  Patch_Apply  (s_iaPatchId);
    else     Patch_Restore(s_iaPatchId);
}

BOOL InstantAbilities_IsEnabled(void)
{
    return (s_iaPatchId >= 0) && Patch_IsApplied(s_iaPatchId);
}

int InstantAbilities_GetPatchId(void) { return s_iaPatchId; }

