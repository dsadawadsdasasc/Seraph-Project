/* instant_abilities.h — Instant Abilities (NOP cooldown decrement + check). */

#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_ia_pat[];
extern const UINT8 k_ia_mask[];

void InstantAbilities_OnAttach(void);
void InstantAbilities_OnDetach(void);

void InstantAbilities_SetEnabled(BOOL en);
BOOL InstantAbilities_IsEnabled(void);

int  InstantAbilities_GetPatchId(void);

/* Pre-scan injection (see revive.h). */
void InstantAbilities_SetPreScanResult(UINT64 matchVA);

#ifdef __cplusplus
}
#endif
