#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_ik_pat[];
extern const UINT8 k_ik_mask[];
void InstaKill_SetPreScanResult(UINT64 va);
void InstaKill_OnAttach(void);
void InstaKill_OnDetach(void);
void InstaKill_SetEnabled(BOOL state);
BOOL InstaKill_IsEnabled(void);
BOOL InstaKill_IsReady(void);

#ifdef __cplusplus
}
#endif
