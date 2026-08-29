
/* noinactivity.c — port of the CE "inactivity_kick_flag" script.
 *
 * The AOB locates a RIP-relative LEA that loads the base of the
 * inactivity-kick flag struct.  The actual flag lives at leaTarget + 8.
 *
 *   48 8D 2D ?? ?? ?? ?? 48 63 C7
 *     lea  rcx, [rip+disp32]        ; 7 bytes — disp32 at matchVA+3
 *     movsxd rax, edi               ; 3 bytes
 *
 *   leaTarget = matchVA + 7 + (INT32)disp32
 *   flagVA    = leaTarget + 8
 *
 * Patch_Register writes zeros to flagVA when the toggle is on; restores
 * the captured original bytes when off.  The MISC tab (tab id = 1) is
 * handled automatically by the generic d2_patches toggle loop. */

#include "ThemidaSDK.h"
#include "noinactivity.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "attach.h"
#include "d2_patches.h"
#include "debug.h"
#include <string.h>

/* ── AOB ─────────────────────────────────────────────────────────────── */






#define NOACT_AOB_LEN   10
#define NOACT_PATCH_LEN 8    /* zero-write width at flagVA */

static int    s_noactPatchId = -1;
static UINT64 s_preScanVA    = 0;

void NoInactivity_SetPreScanResult(UINT64 matchVA) { s_preScanVA = matchVA; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void NoInactivity_OnAttach(void)
{
    MUTATE_START
    s_noactPatchId = -1;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _noact_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        DEBUG_PATCH("NoInactivity: AOB not found");
        goto _noact_end;
    }



    /* Resolve RIP-relative LEA target: next-IP = matchVA+7, disp32 @ matchVA+3 */
    INT32 disp = 0;
    BYOVD_LOCK();
    BOOL rdOk = BYOVD_ReadVA(cr3, matchVA + 3, &disp, 4);
    BYOVD_UNLOCK();
    if (!rdOk) {
        DEBUG_PATCH("NoInactivity: failed to read disp32 at 0x%I64X", matchVA + 3);
        goto _noact_end;
    }
    UINT64 leaTarget = matchVA + 7 + (UINT64)(INT64)disp;
    UINT64 flagVA    = leaTarget + 8;

    DEBUG_PATCH("NoInactivity: match=0x%I64X disp=0x%08X leaTarget=0x%I64X flagVA=0x%I64X",
                matchVA, (UINT32)disp, leaTarget, flagVA);

    /* Write 8 zero bytes to flagVA when enabled; restored to captured
     * original on disable by the generic patch toggle system.            */
    static const UINT8 zeros[NOACT_PATCH_LEN] = { 0,0,0,0, 0,0,0,0 };
    int id = Patch_Register("No Inactivity", flagVA, zeros, NOACT_PATCH_LEN);
    if (id < 0) {
        DEBUG_PATCH("NoInactivity: Patch_Register failed");
        goto _noact_end;
    }
    s_noactPatchId = id;
    D2Patches_SetExternalTabForId(id, 1);   /* MISC tab */
    DEBUG_PATCH("NoInactivity: id=%d flagVA=0x%I64X", id, flagVA);

_noact_end:
    MUTATE_END
}
#pragma optimize("", on)

void NoInactivity_OnDetach(void)
{
    s_noactPatchId = -1;
}

int NoInactivity_GetPatchId(void) { return s_noactPatchId; }

