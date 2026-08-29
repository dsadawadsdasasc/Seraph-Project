#pragma once
#include "byovd.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * weapon_stats.h — Direct-write weapon stat modifier.
 *
 * Depends on rapid_fire being attached first. rapid_fire's hook shellcode
 * captures rsi (weaponSObject*) into the cave at RF_OFF_WEAPON_PTR each
 * weapon tick. This module reads that pointer and applies stat overrides
 * via BYOVD_WriteVA — no additional hooks required.
 *
 * weaponSObject* offsets (IDA-confirmed, build 7.3.x.x):
 *   +0x1314  float   handling delta accumulator
 *   +0x1318  float   handling speed        (base value)
 *   +0x1320  float   stat near handling    (range or stability)
 *   +0x1A2C  float   fire rate delay       <- managed by rapid_fire.c
 *   +0x1A3C  float   reload timer          (countdown; 0.0 = reload done)
 *   +0x2D9C  uint32  encrypted ammo        <- managed by ammo.c
 */

static inline void WeaponStats_OnAttach(void) {}
static inline void WeaponStats_OnDetach(void) {}
static inline BOOL WeaponStats_IsReady(void) { return FALSE; }
static inline UINT64 WeaponStats_GetWeaponPtr(void) { return 0; }
static inline void WeaponStats_SetHandlingMult(float mult) { (void)mult; }
static inline BOOL WeaponStats_IsHandlingEnabled(void) { return FALSE; }
static inline void WeaponStats_SetRangeMult(float mult) { (void)mult; }
static inline BOOL WeaponStats_IsRangeEnabled(void) { return FALSE; }
static inline void WeaponStats_SetReloadMult(float mult) { (void)mult; }
static inline BOOL WeaponStats_IsReloadEnabled(void) { return FALSE; }
static inline void WeaponStats_SetAmmoOverride(BOOL state, UINT32 val) { (void)state; (void)val; }
static inline BOOL WeaponStats_IsAmmoOverrideEnabled(void) { return FALSE; }
static inline void WeaponStats_WriteStat(UINT32 offset, float val) { (void)offset; (void)val; }
static inline void WeaponStats_Tick(void) {}


#ifdef __cplusplus
}
#endif
