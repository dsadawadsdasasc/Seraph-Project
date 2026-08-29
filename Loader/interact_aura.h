#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_itar_pat[];
extern const UINT8 k_itar_mask[];
void InteractAura_SetPreScanResult(UINT64 va);
void InteractAura_OnAttach(void);
void InteractAura_OnDetach(void);
void InteractAura_SetEnabled(BOOL state);
void InteractAura_Tick(void);
BOOL InteractAura_IsEnabled(void);
BOOL InteractAura_IsReady(void);

#ifdef __cplusplus
}
#endif
