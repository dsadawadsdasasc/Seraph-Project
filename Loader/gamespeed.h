#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Patterns exposed for FeatureInitThread batch scan */
extern const UINT8 k_gs_pat[];
extern const UINT8 k_gs_mask[];
void GameSpeed_SetPreScanResult(UINT64 va);

/* Call after AttachToDestiny2 succeeds */
void GameSpeed_OnAttach(void);

/* Set game speed slider value (1-100, inversely proportional) */
void GameSpeed_SetSpeed(int sliderVal);
int  GameSpeed_GetSpeed(void);

/* Set game slow slider value (1-10, directly proportional) */
void GameSpeed_SetSlow(int sliderVal);
int  GameSpeed_GetSlow(void);

/* Call every render frame */
void GameSpeed_Tick(void);

/* Restore original value and reset state */
void GameSpeed_OnDetach(void);

/* Returns TRUE if pattern was found and VA is valid */
BOOL GameSpeed_IsReady(void);

#ifdef __cplusplus
}
#endif
