/* noturnback.c — No Turn Back.
 *
 * AOB:     40 B5 01 F3 0F 58 46 54   (8 bytes anchor: mov bpl,1 + addss xmm0,[rsi+0x54])
 *
 * Two cooperating pieces:
 *   1. Patch  @ matchVA + 0x8   (`movss [rsi+0x54], xmm0`, 5 bytes)
 *      → 5-byte multi-byte NOP `0F 1F 44 00 00` (registered with Patch_Register;
 *        Patch_Apply / Patch_Restore drives the regular toggle).
 *   2. Observer LazyHook @ matchVA + 0x3 (`addss xmm0,[rsi+0x54]`, 5 bytes).
 *      Shellcode: `mov [rip+disp32], rsi`  → stores rsi into a mailbox slot at
 *      caveVA + 0x00 every time the function runs.  Always installed.
 *
 * One-shot zero trigger:
 *   When the user enables the patch, NoTurnBack_TriggerOneShotZero() reads
 *   the latest captured rsi from the mailbox and BYOVD-writes 0.0f to
 *   [rsi + 0x54].  This makes the on-screen turn-back timer disappear
 *   immediately instead of waiting for it to tick down naturally.
 */

#include "ThemidaSDK.h"
#include "noturnback.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "attach.h"
#include "d2_patches.h"
#include "cave_finder.h"
#include "lazyhook.h"
#include "debug.h"
#include <string.h>

#define NTB_AOB_LEN     8
#define NTB_HOOK_OFFSET 0x8
#define NTB_PATCH_LEN   5

#define NTB_CAPT_OFFSET 0x3
#define NTB_CAPT_LEN    5

#define NTB_MBOX_OFF      0x00
#define NTB_SC_OFF        0x08
#define NTB_CAVE_RESERVE  32

static int    s_ntbPatchId = -1;
static int    s_ntbHookId  = -1;
static UINT64 s_ntbCaveVA  = 0;
static UINT64 s_ntbMailbox = 0;
static UINT64 s_preScanVA  = 0;

void NoTurnBack_SetPreScanResult(UINT64 matchVA) { s_preScanVA = matchVA; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void NoTurnBack_OnAttach(void)
{
    MUTATE_START
    s_ntbPatchId = -1;
    s_ntbHookId  = -1;
    s_ntbCaveVA  = 0;
    s_ntbMailbox = 0;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _ntb_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        DEBUG_PATCH("NoTurnBack: AOB not found");
        goto _ntb_end;
    }



    UINT64 hookVA = matchVA + NTB_HOOK_OFFSET;   /* +0x8: movss [rsi+0x54], xmm0 */
    UINT64 captVA = matchVA + NTB_CAPT_OFFSET;   /* +0x3: addss xmm0, [rsi+0x54]  */

    /* ── (1) Register the in-place NOP patch (toggle path is unchanged). ── */
    static const UINT8 nop5[NTB_PATCH_LEN] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    int id = Patch_Register("No Turn Back", hookVA, nop5, NTB_PATCH_LEN);
    if (id < 0) {
        DEBUG_PATCH("NoTurnBack: Patch_Register failed");
        goto _ntb_end;
    }
    s_ntbPatchId = id;
    D2Patches_SetExternalTabForId(id, 1);   /* MISC tab */

    /* ── (2) Install the observer LazyHook for one-shot rsi capture. ───── */
    UINT64 caveVA = CaveFinder_FindFirst(cr3, d2Base, NTB_CAVE_RESERVE);
    if (!caveVA) {
        DEBUG_PATCH("NoTurnBack: cave not found — one-shot zero disabled");
        goto _ntb_done_patch_only;
    }
    CaveFinder_Reserve(caveVA, NTB_CAVE_RESERVE);

    UINT64 mailboxVA = caveVA + NTB_MBOX_OFF;
    UINT64 scBase    = caveVA + NTB_SC_OFF;

    /* mov qword [rip-15], rsi  — stores rsi into mailbox at scBase-15 = mailboxVA */
    static const UINT8 sc[7] = { 0x48, 0x89, 0x35, 0xF1, 0xFF, 0xFF, 0xFF };

    /* Zero the mailbox slot up front. */
    UINT64 zero = 0;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, mailboxVA, &zero, 8);
    BYOVD_UNLOCK();

    int hid = LazyHook_Install(cr3, captVA, NTB_CAPT_LEN, sc, sizeof sc, scBase);
    if (hid < 0) {
        DEBUG_PATCH("NoTurnBack: LazyHook_Install failed — one-shot zero disabled");
        goto _ntb_done_patch_only;
    }
    s_ntbHookId  = hid;
    s_ntbCaveVA  = caveVA;
    s_ntbMailbox = mailboxVA;

    DEBUG_PATCH("NoTurnBack: id=%d match=0x%I64X hook=0x%I64X capt=0x%I64X mbox=0x%I64X",
                id, matchVA, hookVA, captVA, mailboxVA);
    goto _ntb_end;

_ntb_done_patch_only:
    DEBUG_PATCH("NoTurnBack: id=%d match=0x%I64X hook=0x%I64X (no observer hook)",
                s_ntbPatchId, matchVA, hookVA);
_ntb_end:
    MUTATE_END
}
#pragma optimize("", on)

void NoTurnBack_OnDetach(void)
{
    MUTATE_START
    if (s_ntbHookId >= 0) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_ntbHookId, cr3);
    }
    s_ntbPatchId = -1;
    s_ntbHookId  = -1;
    s_ntbCaveVA  = 0;
    s_ntbMailbox = 0;
    MUTATE_END
}

int NoTurnBack_GetPatchId(void)
{
    return s_ntbPatchId;
}

void NoTurnBack_TriggerOneShotZero(void)
{
    if (!s_ntbMailbox) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 rsi = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, s_ntbMailbox, &rsi, 8);
    BYOVD_UNLOCK();
    if (rsi < 0x10000ULL) {
        DEBUG_PATCH("NoTurnBack: one-shot skipped — mailbox=0x%I64X (function not hit yet)", rsi);
        return;
    }

    float zerof = 0.0f;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, rsi + 0x54, &zerof, 4);
    BYOVD_UNLOCK();
    DEBUG_PATCH("NoTurnBack: one-shot zero @ [0x%I64X + 0x54]", rsi);
}

#if 1
/* =========================================================================
   PREVIOUS VERSION (SIMPLIFIED): Direct NOP patch.
   This version is what we were using until now. It is a direct 5-NOP patch
   without any observer hooks or mailbox capture.
   ========================================================================= */
#if 0
void NoTurnBack_OnAttach_Simplified(void)
{
    s_ntbPatchId = -1;
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_ntb_pat, k_ntb_mask, NTB_AOB_LEN);
        BYOVD_UNLOCK();
    }
    if (!matchVA) return;

    UINT64 hookVA = matchVA + NTB_HOOK_OFFSET;
    static const UINT8 nop5[NTB_PATCH_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    int id = Patch_Register("No Turn Back", hookVA, nop5, NTB_PATCH_LEN);
    if (id < 0) return;
    s_ntbPatchId = id;
}
#endif
#endif
