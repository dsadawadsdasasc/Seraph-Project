#include "ThemidaSDK.h"
#include "thirdperson.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include "aob_patterns.h"
#include <string.h>

#define TP_AOB_LEN      7
#define TP_STOLEN_LEN   7
#define TP_CAVE_NEED    64

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static int    s_hookId    = -1;
static BOOL   s_enabled   = FALSE;
static float  s_distance  = 15.0f;

void ThirdPerson_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL ThirdPerson_IsReady(void)               { return s_hookVA != 0 && s_caveVA != 0; }
BOOL ThirdPerson_IsEnabled(void)             { return s_enabled; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void ThirdPerson_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_caveVA = 0;
    s_hookId = -1; s_enabled = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_thirdperson_pat, k_thirdperson_mask, 7);
        BYOVD_UNLOCK();
    }
    if (!matchVA) goto _end;
    s_hookVA = matchVA;


    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindFirst(cr3, d2Base, TP_CAVE_NEED);
    BYOVD_UNLOCK();
    if (!s_caveVA) {
        DEBUG_PATCH("ThirdPerson_OnAttach: cave not found");
        s_hookVA = 0;
        goto _end;
    }
    CaveFinder_Reserve(s_caveVA, TP_CAVE_NEED);

    DEBUG_PATCH("ThirdPerson_OnAttach: ready to hook (cave=0x%I64X)", s_caveVA);

_end:
    MUTATE_END
}
#pragma optimize("", on)

#pragma optimize("", off)
void ThirdPerson_OnDetach(void)
{
    MUTATE_START
    if (s_hookId >= 0) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
    }
    s_hookVA = 0; s_caveVA = 0;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

void ThirdPerson_SetEnabled(BOOL state)
{
    s_enabled = state;
    if (!s_caveVA || !s_hookVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    BYOVD_LOCK();
    if (state) {
        if (s_hookId == -1) {
            /* Shellcode:
             *   mov ecx, float value         ; float value -> B9 [xx xx xx xx]  (5 bytes)
             *   mov [rax+rdi+00000984], ecx  ; write to zoom offset -> 89 8C 38 84 09 00 00 (7 bytes)
             */
            UINT8 sc[12] = {
                0xB9, 0x00, 0x00, 0x70, 0x41,
                0x89, 0x8C, 0x38, 0x84, 0x09, 0x00, 0x00
            };
            *(float*)(sc + 1) = s_distance;
            
            s_hookId = LazyHook_Install(cr3, s_hookVA, TP_STOLEN_LEN,
                                        sc, sizeof(sc), s_caveVA);
            DEBUG_PATCH("ThirdPerson Hook dynamic install id=%d value=%.2f", s_hookId, s_distance);
        }
    } else {
        if (s_hookId >= 0) {
            LazyHook_Remove(s_hookId, cr3);
            DEBUG_PATCH("ThirdPerson Hook dynamic remove id=%d", s_hookId);
            s_hookId = -1;
        }
    }
    BYOVD_UNLOCK();
}

void ThirdPerson_SetDistance(float val)
{
    s_distance = val;
    if (s_hookId >= 0 && s_caveVA) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_caveVA + 1, &s_distance, sizeof(float));
            BYOVD_UNLOCK();
            DEBUG_PATCH("ThirdPerson dynamic distance update value=%.2f", s_distance);
        }
    }
}

float ThirdPerson_GetDistance(void)
{
    return s_distance;
}
