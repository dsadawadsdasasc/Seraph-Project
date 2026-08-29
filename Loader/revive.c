#include "ThemidaSDK.h"
#include "revive.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "tigerlist.h"
#include "local_player.h"

static BOOL s_enabled = FALSE;

#pragma optimize("", off)
void Revive_OnAttach(void)
{
    MUTATE_START
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

#pragma optimize("", off)
void Revive_OnDetach(void)
{
    MUTATE_START
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

void Revive_SetEnabled(BOOL en)
{
    if (s_enabled == en) return;
    s_enabled = en;
}

BOOL Revive_IsEnabled(void)
{
    return s_enabled;
}

BOOL Revive_IsReady(void)
{
    return TigerList_IsReady();
}

void Revive_Tick(void)
{
    if (!s_enabled) return;

    static DWORD s_lastWrite = 0;
    DWORD now = GetTickCount();
    if (now - s_lastWrite < 250) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    int lpIdx = LP_GetLocalPlayerIndex();
    if (lpIdx < 0 || lpIdx >= TL_MAX_SLOTS) return;

    UINT64 container = TigerList_GetContainer();
    if (!container) return;

    UINT64 arrPtr = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, container + 0x08, &arrPtr, 8);
    BYOVD_UNLOCK();
    if (!ok || !arrPtr || arrPtr < 0x10000ULL) return;

    UINT64 slotVA = arrPtr + (UINT64)lpIdx * TL_STRIDE;
    float currentTimer = 0.0f;
    BYOVD_LOCK();
    BOOL rdOk = BYOVD_ReadVA(cr3, slotVA + 0x848, &currentTimer, 4);
    if (rdOk && currentTimer != 0.0f) {
        float zero = 0.0f;
        BYOVD_WriteVA(cr3, slotVA + 0x848, &zero, 4);
    }
    BYOVD_UNLOCK();

    s_lastWrite = now;
}
