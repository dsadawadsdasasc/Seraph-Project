#ifndef SERAPH_EXCLUDE_WEAPON_STATS
#ifndef SERAPH_DMA_BUILD
#include "ThemidaSDK.h"
#include "weapon_stats.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <string.h>
#include "local_player.h"
#include "sobject_list.h"
#include "syscalls.h"

static BOOL s_ready = FALSE;
static BOOL s_handling_enabled = FALSE;
static float s_handling_mult = 1.0f;
static BOOL s_range_enabled = FALSE;
static float s_range_mult = 1.0f;
static BOOL s_reload_enabled = FALSE;
static float s_reload_mult = 1.0f;
static BOOL s_ammo_override_enabled = FALSE;
static UINT32 s_ammo_override_val = 99;

/* Forward declarations */
static void AutoScanWeaponOffsets(UINT64 ent_va, UINT32 idx);

void WeaponStats_OnAttach(void) {
    VM_START
    s_ready = TRUE;
    s_reload_enabled = FALSE;
    s_ammo_override_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

#pragma optimize("", off)
void WeaponStats_OnDetach(void)
{
    MUTATE_START
    s_ready = FALSE;
    s_handling_enabled = FALSE;
    s_range_enabled = FALSE;
    s_reload_enabled = FALSE;
    s_ammo_override_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

BOOL WeaponStats_IsReady(void)
{
    return s_ready;
}

UINT64 WeaponStats_GetWeaponPtr(void)
{
    return 0;
}

void WeaponStats_SetHandlingMult(float mult)
{
    s_handling_mult = mult;
    s_handling_enabled = (mult > 0.0f);
}

BOOL WeaponStats_IsHandlingEnabled(void)
{
    return s_handling_enabled;
}

void WeaponStats_SetRangeMult(float mult)
{
    s_range_mult = mult;
    s_range_enabled = (mult > 0.0f);
}

BOOL WeaponStats_IsRangeEnabled(void)
{
    return s_range_enabled;
}

void WeaponStats_SetReloadMult(float mult)
{
    s_reload_mult = mult;
    s_reload_enabled = (mult > 0.0f);
}

BOOL WeaponStats_IsReloadEnabled(void)
{
    return s_reload_enabled;
}

void WeaponStats_SetAmmoOverride(BOOL state, UINT32 val)
{
    s_ammo_override_enabled = state;
    s_ammo_override_val = val;
}

BOOL WeaponStats_IsAmmoOverrideEnabled(void)
{
    return s_ammo_override_enabled;
}

void WeaponStats_WriteStat(UINT32 offset, float val)
{
    (void)offset;
    (void)val;
}

void WeaponStats_Tick(void)
{
    static DWORD s_last_scan_ms = 0;
    DWORD now = GetTickCount();
    if (now - s_last_scan_ms < 1000) {
        return; /* Scan every 1 second */
    }
    s_last_scan_ms = now;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 lp_tlist_va = LP_GetEntityVA();
    if (!lp_tlist_va) {
        DEBUG_WEAPONS("[AUTO-SCAN] Local player TigerList entry not resolved yet");
        return;
    }

    /* Read player SObject handle from TigerList (offset 0x084) */
    uint32_t lp_sobject_handle = 0;
    BYOVD_LOCK();
    BOOL ok_hdl = BYOVD_ReadVA(cr3, lp_tlist_va + 0x084, &lp_sobject_handle, 4);
    BYOVD_UNLOCK();

    if (!ok_hdl || !SObject_IsValidHandle(lp_sobject_handle)) {
        DEBUG_WEAPONS("[AUTO-SCAN] Player SObject handle (0x%08X) is invalid", lp_sobject_handle);
        return;
    }

    /* Resolve Player SObject handle to get absolute Player SObject pointer */
    UINT64 lp_sobject_va = SObjectList_ResolveHandle(cr3, lp_sobject_handle);
    if (!lp_sobject_va) {
        DEBUG_WEAPONS("[AUTO-SCAN] Failed to resolve Player SObject handle 0x%08X", lp_sobject_handle);
        return;
    }

    DEBUG_WEAPONS("[AUTO-SCAN] Resolved Player SObject at 0x%I64X", lp_sobject_va);

    /* Allocate and read 4KB (0x1000 bytes) of Player SObject structure for scan */
    UINT32 *lp_data = (UINT32*)SeraphHeapAlloc(0x1000);
    if (!lp_data) return;

    memset(lp_data, 0, 0x1000);
    BYOVD_LOCK();
    BOOL ok_read = BYOVD_ReadVA(cr3, lp_sobject_va, lp_data, 0x1000);
    BYOVD_UNLOCK();

    if (!ok_read) {
        DEBUG_WEAPONS("[AUTO-SCAN] Failed to read Player SObject memory at 0x%I64X", lp_sobject_va);
        SeraphHeapFree(lp_data);
        return;
    }

    /* Fetch all Weapon entities from the global SObject list */
    UINT64 array_base = SObjectList_GetArrayBase();
    UINT64 stride = SObjectList_GetStride();
    UINT32 max_count = SObjectList_GetMaxCount();

    if (!array_base || !stride) {
        DEBUG_WEAPONS("[AUTO-SCAN] SObjectList is not ready yet");
        SeraphHeapFree(lp_data);
        return;
    }

    for (UINT32 idx = 0; idx < max_count; idx++) {
        UINT64 ent_va = array_base + (UINT64)idx * stride;
        uint8_t type = 0;
        uint8_t alive = 0;

        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, ent_va + 0x08, &type, 1); /* SOBJ_OFF_TYPE */
        BYOVD_ReadVA(cr3, ent_va + 0x09, &alive, 1); /* SOBJ_OFF_ALIVE */
        BYOVD_UNLOCK();

        if (type == 14 && alive) { /* ObjectType::Weapon = 14 */
            uint32_t weapon_handle = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, ent_va + 0x00, &weapon_handle, 4); /* Handle at base offset 0x00 */
            BYOVD_UNLOCK();

            if (SObject_IsValidHandle(weapon_handle)) {
                /* Scan Player SObject buffer for weapon_handle (aligned to 4 bytes) */
                for (UINT32 off = 0; off < (0x1000 / 4); off++) {
                    if (lp_data[off] == weapon_handle) {
                        DEBUG_WEAPONS("[AUTO-SCAN] MATCH: Active Weapon Handle 0x%08X found at PlayerSObject + 0x%X (SObject=0x%I64X index=%u)",
                                      weapon_handle, off * 4, ent_va, idx);
                    }
                }
            }
        }
    }

    SeraphHeapFree(lp_data);
}
#endif
#endif
