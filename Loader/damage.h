#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Damage Multiplier — direct patch approach.
 * AOB: "80 B9 5C 09 00 00 00 74 09 F3 0F 10 05"
 * Patches 13 bytes at AOB location with:
 *   F3 0F 10 05 [RIP-rel 4] C3 [float 4]
 * Float value lives at offset 0x09 (bytes 9-12).
 */

/* AOB pattern + mask (extern — used by gui_core.cpp scan entry) */
extern const UINT8 k_dmg_pat[];
extern const UINT8 k_dmg_mask[];
#define DMG_AOB_LEN 13

void Damage_OnAttach(void);
void Damage_SetMultiplier(int multValue);
int  Damage_GetMultiplier(void);
void Damage_Tick(void);
void Damage_SetEnabled(BOOL state);
BOOL Damage_IsReady(void);
void Damage_OnDetach(void);

/* Pre-scan result injection (optional, for external AOB scanner) */
void Damage_SetPreScanResult(UINT64 va);

#ifdef __cplusplus
}
#endif
