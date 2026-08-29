#ifndef AURA_H
#define AURA_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_aura_pat[];
extern const UINT8 k_aura_mask[];
void Aura_SetPreScanResult(UINT64 va);
void Aura_OnAttach(void);
int  Aura_GetMultiplier(void);
void Aura_SetMultiplier(int multValue);
void Aura_SetEnabled(BOOL state);
void Aura_Tick(void);
void Aura_OnDetach(void);
BOOL Aura_IsReady(void);

#ifdef __cplusplus
}
#endif

#endif /* AURA_H */
