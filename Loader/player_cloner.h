#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_cloner_pat[];
extern const UINT8 k_cloner_mask[];

#define CLONER_AOB_LEN 26

void PlayerCloner_SetPreScanResult(UINT64 va);
void PlayerCloner_OnAttach(void);
void PlayerCloner_OnDetach(void);
void PlayerCloner_SetEnabled(BOOL state);
BOOL PlayerCloner_IsEnabled(void);
BOOL PlayerCloner_IsReady(void);

#ifdef __cplusplus
}
#endif
