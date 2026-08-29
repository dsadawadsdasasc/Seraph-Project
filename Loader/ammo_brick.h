#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BRICK_AOB_LEN  12

extern const UINT8 k_brick_pat[];
extern const UINT8 k_brick_mask[];

void AmmoBrick_SetPreScanResult(UINT64 va);
void AmmoBrick_OnAttach(void);
BOOL AmmoBrick_IsReady(void);
BOOL AmmoBrick_IsEnabled(void);
void AmmoBrick_SetEnabled(BOOL state);
void AmmoBrick_OnDetach(void);

#ifdef __cplusplus
}
#endif
