
/* health_regen.c — Constant Health Regen
 *
 * CE Script origin (adapted):
 *   aobscanregion: 0F 86 ?? ?? ?? ?? 49 8B 4E ?? 41 8B D7
 *   [ENABLE]  db E9 [rel32+1] 90   (jbe -> unconditional jmp + NOP)
 *   [DISABLE] db 0F 86 [original_rel32]  (restore jbe)
 *
 * Mechanism:
 *   The scanned 'jbe rel32' is a health-regen branch condition.
 *   Replacing it with an unconditional 'jmp' makes health always regen.
 *
 *   'jbe' (0F 86) = 6 bytes.  'jmp rel32' (E9) = 5 bytes.
 *   To keep the same jump TARGET, we add 1 to the original rel32
 *   (because jmp reads next-IP from byte 5 vs jbe from byte 6).
 *   The 6th byte is filled with 0x90 (NOP) to preserve instruction alignment.
 *
 * Thread safety:
 *   All BYOVD calls are wrapped with BYOVD_LOCK/UNLOCK.
 *   OnAttach runs in AutoAttachThread (background). Patch_Toggle runs
 *   from the render thread via the standard g_patchActive toggle handler.
 */

#include "ThemidaSDK.h"
#include "health_regen.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "attach.h"
#include "d2_patches.h"
#include "debug.h"
#include <string.h>

/* ── AOB Pattern ────────────────────────────────────────────────────────────
 *   Byte  0- 1:  0F 86          jbe rel32 opcode     (exact)
 *   Byte  2- 5:  ?? ?? ?? ??    rel32 displacement   (wildcard)
 *   Byte  6- 8:  49 8B 4E       mov rcx,[r14+??]     (exact prefix)
 *   Byte  9   :  ??             byte offset           (wildcard)
 *   Byte 10-12:  41 8B D7       mov edx,r15d          (exact anchor)
 */







#define HRG_AOB_LEN   13
#define HRG_PATCH_LEN  6         /* E9 [rel32+1:4bytes] 90 */
#define HRG_SCAN_SIZE  0x20000000ULL  /* 512MB — health code may be far from base */

static UINT64 s_preScanVA  = 0;
static int s_hrPatchId = -1;    /* Patch_Register ID, or -1 if not found */

/* ─────────────────────────────────────────────────────────────────────────── */

void HealthRegen_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void HealthRegen_OnAttach(void)
{
    MUTATE_START
    s_hrPatchId = -1;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _hroa_end;

    /* ── 1. RVA resolution ────────────────────────────────────────────────── */
    UINT64 matchVA = s_preScanVA;
    if (!matchVA) goto _hroa_end;



    /* ── 2. Read original 6 bytes (0F 86 + rel32) ───────────────────────── */
    UINT8 original[HRG_PATCH_LEN] = {0};
    BYOVD_LOCK();
    if (!BYOVD_ReadVA(cr3, matchVA, original, HRG_PATCH_LEN)) { BYOVD_UNLOCK(); goto _hroa_end; }
    BYOVD_UNLOCK();

    /* Sanity: first two bytes must still be 0F 86 */
    if (original[0] != 0x0F || original[1] != 0x86) goto _hroa_end;

    /* ── 3. Compute patched bytes ────────────────────────────────────────── *
     *  jbe (0F 86) instruction is 6 bytes: opcode(2) + rel32(4)             *
     *    next_IP = matchVA + 6                                               *
     *    target  = matchVA + 6 + orig_rel32                                  *
     *                                                                        *
     *  jmp (E9) instruction is  5 bytes: opcode(1) + rel32(4)               *
     *    next_IP = matchVA + 5                                               *
     *    target  = matchVA + 5 + new_rel32  (must equal original target)     *
     *                                                                        *
     *  => new_rel32 = orig_rel32 + 1                                         *
     *  6th byte = 0x90 (NOP) to fill the space jbe used.                    */
    INT32 orig_rel32 = *(INT32*)(original + 2);
    INT32 new_rel32 = orig_rel32 + 1;

    UINT8 patch[HRG_PATCH_LEN];
    patch[0] = 0xE9;                         /* jmp rel32 opcode */
    *(INT32*)(patch + 1) = new_rel32;        /* 4-byte LE offset */
    patch[5] = 0x90;                         /* NOP to fill 6th byte */

    /* ── 4. Register patch (Patch_Register pre-reads original internally) ── */
    int id = Patch_Register("Constant Health Regen", matchVA, patch, HRG_PATCH_LEN);
    if (id < 0) goto _hroa_end;

    s_hrPatchId = id;
    D2Patches_SetExternalTabForId(id, 11);
_hroa_end:
    MUTATE_END
}
#pragma optimize("", on)

void HealthRegen_OnDetach(void)
{
    s_hrPatchId = -1;
}

int HealthRegen_GetPatchId(void)
{
    return s_hrPatchId;
}

