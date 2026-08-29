
#include "ThemidaSDK.h"
#include "no_recoil.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <string.h>

/* ── No Recoil — direct NOP patch ──────────────────────────────────────────
 * AOB: "48 8B CE E8 ?? ?? ?? ?? 0F B6 44 24 69"
 * Patch offset: 3 (skip 48 8B CE, replace E8 ?? ?? ?? ??)
 * Patch: 5-byte NOP (0F 1F 44 00 00) replaces relative call.
 */

#define NORECOIL_AOB_LEN 13







#define NORECOIL_PATCH_SIZE 5

static UINT64 s_preScanVA = 0;
static UINT64 s_aobVA     = 0;   /* VA of actual patch site (match + 3) */
static BOOL   s_enabled   = FALSE;
static UINT8  s_original[NORECOIL_PATCH_SIZE] = {0};
static BOOL   s_originalSaved = FALSE;

void NoRecoil_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void NoRecoil_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("NoRecoil: new direct-NOP enter");
    s_aobVA = 0;
    s_enabled = FALSE;
    s_originalSaved = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("NoRecoil: no cr3/base"); goto _norecoil_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        WriteLogFile("NoRecoil: AOB NOT FOUND");
        goto _norecoil_end;
    }

    s_aobVA = matchVA + 3; /* skip 48 8B CE */
    { char b[80]; wsprintfA(b,"NoRecoil: AOB at 0x%I64X, patch at 0x%I64X", matchVA, s_aobVA); WriteLogFile(b); }

    /* Verify first byte at patch site is E8 */
    UINT8 check = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, s_aobVA, &check, 1);
    BYOVD_UNLOCK();
    if (check != 0xE8) {
        WriteLogFile("NoRecoil: byte mismatch at AOB (E8 expected)");
        s_aobVA = 0;
        goto _norecoil_end;
    }

    /* Save original 5 bytes */
    BYOVD_LOCK();
    s_originalSaved = BYOVD_ReadVA(cr3, s_aobVA, s_original, NORECOIL_PATCH_SIZE);
    BYOVD_UNLOCK();
    if (!s_originalSaved) {
        WriteLogFile("NoRecoil: failed to save original bytes");
        s_aobVA = 0;
    }
_norecoil_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL NoRecoil_IsReady(void)   { return s_aobVA != 0 && s_originalSaved; }
BOOL NoRecoil_IsEnabled(void) { return s_enabled; }

void NoRecoil_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !NoRecoil_IsReady()) return;
    s_enabled = state;

    if (state) {
        /* Enable: write 5-byte NOP */
        static const UINT8 nop[5] = {0x0F, 0x1F, 0x44, 0x00, 0x00};
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_aobVA, nop, NORECOIL_PATCH_SIZE);
        BYOVD_UNLOCK();
        DEBUG_LOG_TO("norecoil.log", "NORECOIL", "NoRecoil: enabled (NOP at 0x%I64X)", s_aobVA);
    } else {
        /* Disable: restore original bytes */
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_aobVA, s_original, NORECOIL_PATCH_SIZE);
        BYOVD_UNLOCK();
        DEBUG_LOG_TO("norecoil.log", "NORECOIL", "NoRecoil: disabled, original restored at 0x%I64X", s_aobVA);
    }
}

#pragma optimize("", off)
void NoRecoil_OnDetach(void)
{
    MUTATE_START
    if (s_enabled && NoRecoil_IsReady()) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_aobVA, s_original, NORECOIL_PATCH_SIZE);
            BYOVD_UNLOCK();
        }
    }
    s_aobVA = 0;
    s_enabled = FALSE;
    s_originalSaved = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

