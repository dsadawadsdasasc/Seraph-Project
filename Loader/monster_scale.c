#include "monster_scale.h"
#include "sobject.h"
#include "sobject_list.h"
#include "byovd.h"
#include <string.h>

static volatile LONG  s_monsterScaleEnabled = 0;
static volatile int   s_monsterScaleVal     = MONSTER_SCALE_DEFAULT; /* -10..10 -> -2.0f..2.0f, default 5 = 1.0f */

void MonsterScale_SetEnabled(BOOL enable)
{
    InterlockedExchange(&s_monsterScaleEnabled, enable ? 1 : 0);
    if (!enable) {
        /* Restore default scale 1.0f on all active alive PvE entities */
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3 && SObjectList_IsReady()) {
            UINT64 baseVA = SObjectList_GetArrayBase();
            UINT32 maxCount = SObjectList_GetMaxCount();
            if (maxCount > SOBJ_MAX_COUNT) maxCount = SOBJ_MAX_COUNT;

            for (UINT32 i = 0; i < maxCount; i++) {
                SObjectRaw raw;
                if (!SObjectList_ReadEntity(i, &raw)) continue;

                /* IGNORE DEAD ENTITIES: raw.alive == 0 (at +0x0B) */
                if (raw.alive == 0) continue;

                if (SObject_IsPvEEnemy(raw.type_flags, raw.type)) {
                    UINT64 entryVA = baseVA + (UINT64)i * SOBJ_STRIDE;
                    uint32_t current_enc = 0;
                    BYOVD_LOCK();
                    BOOL ok = BYOVD_ReadVA(cr3, entryVA + SOBJ_OFF_ENC_SCALE, &current_enc, 4);
                    if (ok && current_enc != 0) {
                        uint32_t default_f = 0x3F800000u; /* 1.0f */
                        uint32_t scale_key = SObject_DeriveScaleKey(current_enc);
                        uint32_t enc_1 = default_f ^ scale_key;
                        BYOVD_WriteVA(cr3, entryVA + SOBJ_OFF_ENC_SCALE, &enc_1, 4);
                    }
                    BYOVD_UNLOCK();
                }
            }
        }
    }
}

BOOL MonsterScale_IsEnabled(void)
{
    return InterlockedCompareExchange(&s_monsterScaleEnabled, 0, 0) == 1;
}

void MonsterScale_SetVal(int val)
{
    if (val < -10) val = -10;
    if (val >  10) val =  10;
    s_monsterScaleVal = val;
}

int MonsterScale_GetVal(void)
{
    return s_monsterScaleVal;
}

void MonsterScale_Reset(void)
{
    s_monsterScaleVal = MONSTER_SCALE_DEFAULT;
}

void MonsterScale_Tick(void)
{
    if (!MonsterScale_IsEnabled()) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !SObjectList_IsReady()) return;

    UINT64 baseVA = SObjectList_GetArrayBase();
    if (!baseVA) return;

    UINT32 maxCount = SObjectList_GetMaxCount();
    if (maxCount > SOBJ_MAX_COUNT) maxCount = SOBJ_MAX_COUNT;

    /* Slider -10..10 -> Float -2.0f..2.0f (val 5 = 1.0f) */
    float targetScale = (float)s_monsterScaleVal / 5.0f;

    for (UINT32 i = 0; i < maxCount; i++) {
        SObjectRaw raw;
        if (!SObjectList_ReadEntity(i, &raw)) continue;

        /* CRITICAL: Strict Alive Check (+0x0B). Ignore dead/despawned entities! */
        if (raw.alive == 0) continue;

        /* Filter strictly for PvE Enemies (type_flags 0x03, type 0x0C) */
        if (SObject_IsPvEEnemy(raw.type_flags, raw.type)) {
            UINT64 entryVA = baseVA + (UINT64)i * SOBJ_STRIDE;
            uint32_t current_enc = 0;

            BYOVD_LOCK();
            BOOL ok = BYOVD_ReadVA(cr3, entryVA + SOBJ_OFF_ENC_SCALE, &current_enc, 4);
            BYOVD_UNLOCK();

            if (!ok || current_enc == 0) continue;

            uint32_t target_u32 = 0;
            memcpy(&target_u32, &targetScale, 4);

            /* Derive key & encrypt target float for this entity */
            uint32_t scale_key = SObject_DeriveScaleKey(current_enc);
            uint32_t enc_target_u32 = target_u32 ^ scale_key;

            /* Write encrypted float scale to +0xDC */
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, entryVA + SOBJ_OFF_ENC_SCALE, &enc_target_u32, 4);
            BYOVD_UNLOCK();
        }
    }
}
