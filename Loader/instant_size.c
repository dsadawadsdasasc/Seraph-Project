#include "instant_size.h"
#include "sobject.h"
#include "sobject_list.h"
#include "local_player.h"
#include "byovd.h"
#include "byovd_lock.h"
#include <string.h>

static volatile LONG  s_instantSizeEnabled = 0;
static volatile int   s_instantIntVal       = INSTANT_SIZE_DEFAULT; /* -1..2 -> float -1.0f..2.0f, default 1 = 1.0f */
static UINT64         s_cachedLpSObjectVA   = 0;
static DWORD          s_lastScanMs          = 0;

void InstantSize_SetEnabled(BOOL enable)
{
    InterlockedExchange(&s_instantSizeEnabled, enable ? 1 : 0);
    if (!enable) {
        UINT64 lpSobjVA = s_cachedLpSObjectVA;
        if (!lpSobjVA) lpSobjVA = LP_GetLocalPlayerSObjectVA();
        if (lpSobjVA >= 0x10000ULL) {
            /* Restore default scale 1.0f on disable */
            UINT64 cr3 = GetDestiny2CR3();
            if (cr3) {
                uint32_t current_enc = 0;
                BYOVD_LOCK();
                BOOL ok = BYOVD_ReadVA(cr3, lpSobjVA + SOBJ_OFF_ENC_SCALE, &current_enc, 4);
                if (ok && current_enc != 0) {
                    uint32_t default_f = 0x3F800000u; /* 1.0f in float hex */
                    uint32_t scale_key = SObject_DeriveScaleKey(current_enc);
                    uint32_t enc_1 = default_f ^ scale_key;
                    BYOVD_WriteVA(cr3, lpSobjVA + SOBJ_OFF_ENC_SCALE, &enc_1, 4);
                }
                BYOVD_UNLOCK();
            }
        }
    }
}

BOOL InstantSize_IsEnabled(void)
{
    return InterlockedCompareExchange(&s_instantSizeEnabled, 0, 0) == 1;
}

void InstantSize_SetIntVal(int scaledVal)
{
    if (scaledVal < -1) scaledVal = -1;
    if (scaledVal >   2) scaledVal =  2;
    s_instantIntVal = scaledVal;
}

int InstantSize_GetIntVal(void)
{
    return s_instantIntVal;
}

void InstantSize_Reset(void)
{
    s_instantIntVal = INSTANT_SIZE_DEFAULT;
}

void InstantSize_Tick(void)
{
    if (!InstantSize_IsEnabled()) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    DWORD now = GetTickCount();

    /* Refresh SObject local player VA directly from Local Player resolver */
    if (s_cachedLpSObjectVA == 0 || (now - s_lastScanMs > 1000)) {
        s_lastScanMs = now;
        s_cachedLpSObjectVA = LP_GetLocalPlayerSObjectVA();
    }

    if (s_cachedLpSObjectVA < 0x10000ULL) return;

    /* Read current encrypted float scale at +0xDC */
    uint32_t current_enc = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, s_cachedLpSObjectVA + SOBJ_OFF_ENC_SCALE, &current_enc, 4);
    BYOVD_UNLOCK();

    if (!ok || current_enc == 0) return;

    /* Prepare target float value: slider -1..2 -> float -1.0f..2.0f */
    float targetScale = (float)s_instantIntVal;
    uint32_t target_u32 = 0;
    memcpy(&target_u32, &targetScale, 4);

    /* Derive scale encryption key & encrypt target float */
    uint32_t scale_key = SObject_DeriveScaleKey(current_enc);
    uint32_t enc_target_u32 = target_u32 ^ scale_key;

    /* Write encrypted float to SObject +0xDC */
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_cachedLpSObjectVA + SOBJ_OFF_ENC_SCALE, &enc_target_u32, 4);
    BYOVD_UNLOCK();
}
