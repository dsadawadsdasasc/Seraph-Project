#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MS_AOB_LEN  15

extern const UINT8 k_ms_pat[];
extern const UINT8 k_ms_mask[];

void MSpeed_SetPreScanResult(UINT64 va);
void MSpeed_OnAttach(void);
BOOL MSpeed_IsReady(void);
BOOL MSpeed_IsEnabled(void);
void MSpeed_SetEnabled(BOOL state);
void MSpeed_SetValue(float val);
void MSpeed_OnDetach(void);

#ifdef __cplusplus
}
#endif
