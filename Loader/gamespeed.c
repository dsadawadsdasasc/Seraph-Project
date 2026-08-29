
/* gamespeed.c -- Game Speed / Game Slow feature
 *
 * AOB (8 bytes, denso, sem wildcards):
 *   80 00 80 37   = float anterior ao alvo (0x37800080)
 *   00 5B 24 49   = 673200.0f              (0x49245B00) ← alvo
 * Target: match + 0x4
 *
 * NOTA: scan size deve ser >= 0x10000000 (256MB) pois o alvo está
 * a ~164MB da image base. Scan de 128MB nunca encontrava o padrão.
 *
 * BYOVD escreve na RAM física diretamente — page protection ignorada.
 */

#include "ThemidaSDK.h"
#include "xor_strings.h"
#include <windows.h>
#include <math.h>
#include "gamespeed.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <stdio.h>

/* ── AOB pattern + mask (8 bytes, denso, sem wildcards) ─────────────────── */







#define GS_AOB_LEN        8
#define GS_VALUE_OFFSET   0x4      /* 673200.0f está em match + 0x4 */
#define GS_SCAN_SIZE      0x20000000ULL  /* 512MB — alvo pode estar além de 256MB */
#define GS_TICK_MS        50

#define GS_DEFAULT_VAL    673200.0f
#define GS_SPEED_MIN      800.0f
#define GS_SLOW_MAX       6732000.0f

/* ── State ──────────────────────────────────────────────────────────────── */
static UINT64 s_preScanVA = 0;  /* result pre-cached by FeatureInitThread batch scan */
static UINT64 s_targetVA  = 0;
static int    s_speedSlider = 1;   /* 1-100 */
static int    s_slowSlider  = 1;   /* 1-10  */
static DWORD  s_lastTick   = 0;
static BOOL   s_dirty      = FALSE; /* need to write on next tick */

/* Last mode: 0=none/default, 1=speed, 2=slow */
static int s_lastMode = 0;

/* ── Helpers ────────────────────────────────────────────────────────────── */
static float SpeedSliderToFloat(int s)
{
    /* s=100 -> GS_SPEED_MIN, s=1 -> GS_DEFAULT_VAL */
    float frac = (float)(100 - s) / 99.0f;
    return GS_SPEED_MIN + frac * (GS_DEFAULT_VAL - GS_SPEED_MIN);
}

static float SlowSliderToFloat(int s)
{
    /* s=1 -> GS_DEFAULT_VAL, s=10 -> GS_SLOW_MAX */
    float frac = (float)(s - 1) / 9.0f;
    return GS_DEFAULT_VAL + frac * (GS_SLOW_MAX - GS_DEFAULT_VAL);
}

static BOOL WriteFloat(UINT64 cr3, UINT64 va, float val)
{
    return BYOVD_WriteVA(cr3, va, &val, 4);
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void GameSpeed_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#pragma optimize("", off)
void GameSpeed_OnAttach(void)
{
    MUTATE_START
    s_targetVA   = 0;
    s_speedSlider = 1;
    s_slowSlider  = 1;
    s_lastMode   = 0;
    s_dirty      = FALSE;
    s_lastTick   = 0;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    DEBUG_GS("=== GameSpeed_OnAttach: cr3=0x%I64X base=0x%I64X ===", cr3, d2Base);
    if (!cr3 || !d2Base) goto _gsoa_end;

    UINT64 matchVA = 0;
    if (s_preScanVA) {
        matchVA = s_preScanVA;
    } else {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternData(cr3, d2Base, k_gs_pat, k_gs_mask, GS_AOB_LEN);
        BYOVD_UNLOCK();
        if (!matchVA) {
            matchVA = d2Base + SecureReadStatic(&OBF_OFF_GameSpeed);
        }
    }
    if (!matchVA) {
        DEBUG_GS("GameSpeed_OnAttach: no match found");
        goto _gsoa_end;
    }
    BYOVD_LOCK();
    UINT64 candidateVA = matchVA + GS_VALUE_OFFSET;
    float  currentVal  = 0.0f;
    if (!BYOVD_ReadVA(cr3, candidateVA, &currentVal, 4)) {
        BYOVD_UNLOCK();
        {
            char b[128]; wsprintfA(b, "GameSpeed: readback FAILED at 0x%I64X", candidateVA);
            WriteLogFile(b);
        }
        goto _gsoa_end;
    }
    {
        char b[160];
        wsprintfA(b, "GameSpeed: match=0x%I64X candidateVA=0x%I64X val_int=%d (expect ~673200)",
                  matchVA, candidateVA, (int)currentVal);
        WriteLogFile(b);
    }
    /* Wide sanity check: reject only obviously wrong values (negative, zero,
     * or completely out of scale).  The strict ±5% check was too fragile   
     * across game patches; log a warning but accept anything plausible.    */
    if (currentVal <= 0.0f || currentVal > 67320000.0f) {
        BYOVD_UNLOCK();
        {
            char b[128]; wsprintfA(b, "GameSpeed: REJECTED val=%.1f (out of plausible range)", currentVal);
            WriteLogFile(b);
        }
        goto _gsoa_end;
    }
    if (currentVal < GS_DEFAULT_VAL * 0.1f || currentVal > GS_DEFAULT_VAL * 10.0f) {
        WriteLogFile("GameSpeed: WARNING val far from default — accepting anyway");
    }

    s_targetVA = candidateVA;
    BYOVD_UNLOCK();
    {
        char b[128]; wsprintfA(b, "GameSpeed: READY targetVA=0x%I64X val=%d", s_targetVA, (int)currentVal);
        WriteLogFile(b);
    }
_gsoa_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL GameSpeed_IsReady(void)
{
    return s_targetVA != 0;
}

void GameSpeed_SetSpeed(int sliderVal)
{
    if (sliderVal < 1)   sliderVal = 1;
    if (sliderVal > 100) sliderVal = 100;
    s_speedSlider = sliderVal;
    s_lastMode    = (sliderVal == 1) ? 0 : 1;
    s_dirty       = TRUE;
}

int GameSpeed_GetSpeed(void)
{
    return s_speedSlider;
}

void GameSpeed_SetSlow(int sliderVal)
{
    if (sliderVal < 1)  sliderVal = 1;
    if (sliderVal > 10) sliderVal = 10;
    s_slowSlider = sliderVal;
    s_lastMode   = (sliderVal == 1) ? 0 : 2;
    s_dirty      = TRUE;
}

int GameSpeed_GetSlow(void)
{
    return s_slowSlider;
}

void GameSpeed_Tick(void)
{
    if (!s_targetVA) return;
    if (!s_dirty)    return;

    DWORD now = GetTickCount();
    if (now - s_lastTick < GS_TICK_MS) return;
    s_lastTick = now;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    float val;
    if (s_lastMode == 1) {
        val = SpeedSliderToFloat(s_speedSlider);
    } else if (s_lastMode == 2) {
        val = SlowSliderToFloat(s_slowSlider);
    } else {
        val = GS_DEFAULT_VAL;
        s_dirty = FALSE; /* written once, no need to keep writing default */
    }

    if (BYOVD_TRYLOCK()) {
        /* OPT-L3: Lemos o valor atual primeiro — se já estiver correto, pulamos a escrita.
         * Isso evita spam de writes na RAM física (e L1 cache invalidations) a cada 50ms. */
        float currVal = 0.0f;
        if (!BYOVD_ReadVA(cr3, s_targetVA, &currVal, 4) || currVal != val) {
            if (!WriteFloat(cr3, s_targetVA, val))
                DEBUG_GS("GameSpeed_Tick: write FAILED at 0x%I64X val=%.1f", s_targetVA, val);
            else
                DEBUG_GS("GameSpeed_Tick: wrote %.1f -> 0x%I64X (mode=%d)", val, s_targetVA, s_lastMode);
        }
        BYOVD_UNLOCK();
    } else {
        DEBUG_GS("GameSpeed_Tick: lock busy (scan in progress), skipping this tick");
    }

    /* Keep writing while active so game doesn't revert */
    if (s_lastMode != 0) s_dirty = TRUE;
}

#pragma optimize("", off)
void GameSpeed_OnDetach(void)
{
    MUTATE_START
    DEBUG_GS("=== GameSpeed_OnDetach ===");
    if (s_targetVA) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            WriteFloat(cr3, s_targetVA, GS_DEFAULT_VAL);
            BYOVD_UNLOCK();
        }
    }
    s_targetVA    = 0;
    s_speedSlider = 1;
    s_slowSlider  = 1;
    s_lastMode    = 0;
    s_dirty       = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

