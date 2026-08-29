#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_gsize_pat[];
extern const UINT8 k_gsize_mask[];
void Guardian_SetPreScanResult(UINT64 va);

/* Find the guardian size float in memory. Must be called after AttachToDestiny2(). */
void Guardian_OnAttach(void);

/* Set size value: scaledVal in -100..200 → -1.00..2.00 as float written to game. */
void Guardian_SetValue(int scaledVal);
int  Guardian_GetValue(void);

/* Enable / disable. On disable, restores 1.0f immediately. */
void Guardian_SetEnabled(BOOL state);
BOOL Guardian_IsEnabled(void);
BOOL Guardian_IsReady(void);

/* Restore 1.0f, reset internal value to 100. */
void Guardian_Reset(void);

/* Periodic write (call every render frame). */
void Guardian_Tick(void);

/* Restore 1.0f and clear state (call on detach / loader exit). */
void Guardian_OnDetach(void);

#ifdef __cplusplus
}
#endif
