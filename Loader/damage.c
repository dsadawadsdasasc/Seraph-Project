
#include "ThemidaSDK.h"
#include "damage.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"

/* ── Damage Multiplier — direct patch ──────────────────────────────────────
 * AOB: "80 B9 5C 09 00 00 00 74 09 F3 0F 10 05"
 * At offset 0:  cmp byte [rcx+0x95C], 0
 * At offset 7:  je +9 (skip movss)
 * At offset 9:  movss xmm0, [rip+?]   <-- we replace this with our float
 *
 * Patch layout (13 bytes):
 *   +0: F3 0F 10 05 [RIP-rel 4]   movss xmm0, [rip+next_instr+4]
 *   +9: C3                         ret  (nop out the je so we always execute)
 *   +9: [float 4 bytes]           our damage multiplier as float
 *
 * Float lives at offset 0x09 within the patch (bytes 9-12).
 * Original 13 bytes saved for restore on disable.
 */

#define DMG_AOB_LEN      13
#define DMG_PATCH_OFFSET  9  /* where the float lives in our patch */







#define DMG_SCAN_SIZE  0x20000000ULL /* 512MB */

static UINT64      s_preScanVA = 0;
static UINT64      s_dmgVA     = 0;  /* VA of AOB match */
static int         s_dmgValue  = 100;
static BOOL        s_enabled   = FALSE;
static BOOL        s_dirty     = FALSE;
static UINT8       s_original[DMG_AOB_LEN] = {0}; /* saved original bytes */
static BOOL        s_originalSaved = FALSE;

void Damage_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

/* Build the 13-byte patch for a given float scale */
static void BuildPatch(float scale, UINT8 out[DMG_AOB_LEN])
{
    uint32_t bits;
    memcpy(&bits, &scale, 4);
    /* F3 0F 10 05 [01 00 00 00] = movss xmm0, [rip+1] (points to C3+1 = float at +9) */
    out[0]  = 0xF3;
    out[1]  = 0x0F;
    out[2]  = 0x10;
    out[3]  = 0x05;
    out[4]  = 0x01;
    out[5]  = 0x00;
    out[6]  = 0x00;
    out[7]  = 0x00;
    out[8]  = 0xC3;
    out[9]  = (UINT8)(bits);
    out[10] = (UINT8)(bits >> 8);
    out[11] = (UINT8)(bits >> 16);
    out[12] = (UINT8)(bits >> 24);
}

#include "xor_strings.h"

#pragma optimize("", off)
void Damage_OnAttach(void)
{
    MUTATE_START
    s_dmgVA = 0;
    s_enabled = FALSE;
    s_dirty = FALSE;
    s_originalSaved = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("Dmg: no cr3/base"); goto _doa_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        WriteLogFile("Dmg: AOB NOT FOUND");
        goto _doa_end;
    }

    s_dmgVA = matchVA;

    { char b[80]; wsprintfA(b,"Dmg: AOB found at 0x%I64X", matchVA); WriteLogFile(b); }

    /* Save original bytes */
    BYOVD_LOCK();
    s_originalSaved = BYOVD_ReadVA(cr3, s_dmgVA, s_original, DMG_AOB_LEN);
    BYOVD_UNLOCK();
    if (!s_originalSaved) {
        WriteLogFile("Dmg: failed to read original bytes");
        s_dmgVA = 0;
    }
_doa_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL Damage_IsReady(void)
{
    return s_dmgVA != 0 && s_originalSaved;
}

void Damage_SetMultiplier(int multValue)
{
    s_dmgValue = multValue;
    s_dirty = TRUE;
}

int Damage_GetMultiplier(void)
{
    return s_dmgValue;
}

void Damage_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    s_enabled = state;
    s_dirty = TRUE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !Damage_IsReady()) return;

    if (state) {
        /* Enable: write patch with current float */
        UINT8 patch[DMG_AOB_LEN];
        BuildPatch((float)s_dmgValue, patch);
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_dmgVA, patch, DMG_AOB_LEN);
        BYOVD_UNLOCK();
        DEBUG_DAMAGE("Damage: enabled with %.1f at 0x%I64X", (float)s_dmgValue, s_dmgVA);
    } else {
        /* Disable: restore original bytes */
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_dmgVA, s_original, DMG_AOB_LEN);
        BYOVD_UNLOCK();
        DEBUG_DAMAGE("Damage: disabled, original restored at 0x%I64X", s_dmgVA);
    }
}

void Damage_Tick(void)
{
    if (!s_enabled || !s_dirty || !Damage_IsReady()) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    /* Update float at patch offset 9 */
    float fval = (float)s_dmgValue;
    if (BYOVD_TRYLOCK()) {
        if (BYOVD_WriteVA(cr3, s_dmgVA + DMG_PATCH_OFFSET, &fval, 4)) {
            s_dirty = FALSE;
        }
        BYOVD_UNLOCK();
    }
}

#pragma optimize("", off)
void Damage_OnDetach(void)
{
    MUTATE_START
    /* Always restore if we have original bytes — even if the user toggled
     * damage OFF before closing the cheat.  The patch may still be written
     * in the game; s_enabled just tracks GUI toggle state. */
    if (Damage_IsReady()) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_dmgVA, s_original, DMG_AOB_LEN);
            BYOVD_UNLOCK();
        }
    }
    s_dmgVA = 0;
    s_enabled = FALSE;
    s_dirty = FALSE;
    s_originalSaved = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

