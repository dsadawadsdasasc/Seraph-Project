#ifndef SERAPH_DMA_BUILD
#include "ThemidaSDK.h"
#include "infinite_ammo.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "patch.h"
#include "debug.h"
#include <string.h>

/* ── Infinite Magazine — direct NOP patch ──────────────────────────────────
 * AOB: "41 2B D5 49 8B CE E8 ?? ?? ?? ??"
 * At offset 0: sub edx, r13d  (41 2B D5) — this is the magazine decrement.
 *
 * Patch: replace first 3 bytes (41 2B D5) with 0F 1F 00 (3-byte NOP).
 * No code cave, no lazy hook, no shellcode — just a 3-byte NOP.
 * Original bytes saved for restore on disable.
 */

#define AMMO_AOB_LEN      11
#define AMMO_PATCH_SIZE   3

static const UINT8 s_ammo_pat[AMMO_AOB_LEN] = {
    0x41, 0x2B, 0xD5, 0x49, 0x8B, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const UINT8 s_ammo_mask[AMMO_AOB_LEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const UINT8 k_ammo_patch[AMMO_PATCH_SIZE] = { 0x0F, 0x1F, 0x00 };

static UINT64 s_aobVA = 0;
static BOOL   s_enabled = FALSE;
static UINT8  s_original[AMMO_PATCH_SIZE];
static BOOL   s_originalSaved = FALSE;

void InfiniteAmmo_SetPreScanResult(UINT64 va)
{
    s_aobVA = va;
}

#include "xor_strings.h"

#pragma optimize("", off)
#include "aob_patterns.h"

#pragma optimize("", off)
void InfiniteAmmo_OnAttach(void)
{
    MUTATE_START
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 d2base = GetDestiny2Base();
    if (d2base && !s_aobVA) {
        BYOVD_LOCK();
        s_aobVA = BYOVD_ScanPatternText(cr3, d2base, k_ammo_pat, k_ammo_mask, 11);
        BYOVD_UNLOCK();
    }


    if (!s_aobVA) {
        DEBUG_WEAPONS("[InfAmmo] Init failed: AOB not found");
        return;
    }


    /* Read original bytes so we can restore them */
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, s_aobVA, s_original, AMMO_PATCH_SIZE);
    BYOVD_UNLOCK();

    if (ok) {
        s_originalSaved = TRUE;
        DEBUG_WEAPONS("[InfAmmo] Attached. Saved original bytes: %02X %02X %02X", s_original[0], s_original[1], s_original[2]);
    } else {
        DEBUG_WEAPONS("[InfAmmo] Attach failed: could not read original bytes");
    }
    MUTATE_END
}
#pragma optimize("", on)

BOOL InfiniteAmmo_IsEnabled(void)
{
    return s_enabled;
}

BOOL InfiniteAmmo_IsReady(void)
{
    return s_originalSaved;
}

void InfiniteAmmo_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    s_enabled = state;

    if (InfiniteAmmo_IsReady()) {
        if (state) {
            /* Enable: write 3-byte NOP (0F 1F 00) over 41 2B D5 */
            static const UINT8 nop[3] = {0x0F, 0x1F, 0x00};
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_aobVA, nop, AMMO_PATCH_SIZE);
            BYOVD_UNLOCK();
            DEBUG_LOG_TO("infinite_ammo.log", "AMMO", "InfiniteAmmo: enabled (NOP at 0x%I64X)", s_aobVA);
        } else {
            /* Disable: restore original bytes */
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_aobVA, s_original, AMMO_PATCH_SIZE);
            BYOVD_UNLOCK();
            DEBUG_LOG_TO("infinite_ammo.log", "AMMO", "InfiniteAmmo: disabled, original restored at 0x%I64X", s_aobVA);
        }
    }

    /* Coupled feature: Infinite Sword Ammo (hidden patch with tab=0 in d2_patches.c) */
    for (int pi = 0; pi < Patch_Count(); pi++) {
        const char *pn = Patch_GetName(pi);
        if (pn && strcmp(pn, "Infinite Sword Ammo") == 0) {
            if (state) Patch_Apply(pi);
            else Patch_Restore(pi);
            break;
        }
    }
}

#pragma optimize("", off)
void InfiniteAmmo_OnDetach(void)
{
    MUTATE_START
    if (s_enabled && InfiniteAmmo_IsReady()) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_aobVA, s_original, AMMO_PATCH_SIZE);
            BYOVD_UNLOCK();
        }
    }
    s_aobVA = 0;
    s_enabled = FALSE;
    s_originalSaved = FALSE;
    MUTATE_END
}
#pragma optimize("", on)
#endif


