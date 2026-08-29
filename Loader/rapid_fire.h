#pragma once
#include "byovd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_rof_pat[];
extern const UINT8 k_rof_mask[];

#define RF_OFF_ENABLED     0x00
#define RF_OFF_MULT        0x04

void   RapidFire_SetPreScanResult(UINT64 va);
void   RapidFire_OnAttach(void);
void   RapidFire_OnDetach(void);
BOOL   RapidFire_IsReady(void);
BOOL   RapidFire_IsEnabled(void);
void   RapidFire_SetEnabled(BOOL state);
void   RapidFire_SetMultiplier(float mult);

#ifdef __cplusplus
}
#endif
