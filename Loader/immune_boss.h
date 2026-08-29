#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_ib_pat[];
extern const UINT8 k_ib_mask[];
void ImmuneBoss_SetPreScanResult(UINT64 va);
void ImmuneBoss_OnAttach(void);
void ImmuneBoss_OnDetach(void);
void ImmuneBoss_SetEnabled(BOOL state);
void ImmuneBoss_Tick(void);
BOOL ImmuneBoss_IsEnabled(void);
BOOL ImmuneBoss_IsReady(void);

#ifdef __cplusplus
}
#endif
