
#include "ThemidaSDK.h"
#include "guardian.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"

/* AOB: 00 00 80 3F 80 F0 FA 02  (100% unique in the module)
 *      ^^^^^^^^^^^^ = 1.0f (default guardian size float)
 *      The matched VA IS the float to write — range -1.0f .. 2.0f */







#define GSIZE_AOB_LEN   8
#define GSIZE_DEFAULT   100            /* 100 / 100 = 1.0f */

static UINT64 s_preScanVA = 0;
static UINT64 s_va        = 0;
static volatile BOOL   s_enabled   = FALSE;
static volatile int    s_scaledVal = GSIZE_DEFAULT; /* -100..200 → -1.00f..2.00f */

/* ── helpers ─────────────────────────────────────────────────────────────── */
static void WriteFloat(float fval) {
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !s_va) return;
    if (BYOVD_TRYLOCK()) {
        BYOVD_WriteVA(cr3, s_va, &fval, 4);
        BYOVD_UNLOCK();
    }
}

/* ── public API ──────────────────────────────────────────────────────────── */
void Guardian_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#include "xor_strings.h"

#pragma optimize("", off)
void Guardian_OnAttach(void) {
    MUTATE_START
    s_va = 0; s_enabled = FALSE;
    s_scaledVal = GSIZE_DEFAULT;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _goa_end;

    if (s_preScanVA) {
        s_va = s_preScanVA;
    } else {
        BYOVD_LOCK();
        UINT64 matchVA = BYOVD_ScanPatternData(cr3, d2Base, k_gsize_pat, k_gsize_mask, GSIZE_AOB_LEN);
        BYOVD_UNLOCK();
        if (!matchVA) {
            matchVA = d2Base + SecureReadStatic(&OBF_OFF_Guardian);
        }
        s_va = matchVA;
    }
_goa_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL Guardian_IsReady(void)   { return s_va != 0; }
BOOL Guardian_IsEnabled(void) { return s_enabled; }
int  Guardian_GetValue(void)  { return s_scaledVal; }

void Guardian_SetValue(int scaledVal) {
    if (scaledVal < -100) scaledVal = -100;
    if (scaledVal >  200) scaledVal =  200;
    if (s_scaledVal == scaledVal) return;
    s_scaledVal = scaledVal;
    WriteFloat((float)scaledVal / 100.0f);
}

void Guardian_SetEnabled(BOOL state) {
    if (s_enabled == state) return;
    s_enabled = state;
    if (!state) WriteFloat(1.0f);
    else        WriteFloat((float)s_scaledVal / 100.0f);
}

void Guardian_Reset(void) {
    s_scaledVal = GSIZE_DEFAULT;
    WriteFloat(1.0f);
}

void Guardian_Tick(void) {
    /* All writes happen instantly via SetValue/SetEnabled — no periodic tick needed. */
    (void)0;
}

#pragma optimize("", off)
void Guardian_OnDetach(void) {
    MUTATE_START
    if (s_enabled && s_va) WriteFloat(1.0f);
    s_va = 0; s_enabled = FALSE;
    s_scaledVal = GSIZE_DEFAULT;
    MUTATE_END
}
#pragma optimize("", on)

