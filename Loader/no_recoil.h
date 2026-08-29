#ifndef SERAPH_NORECOIL_H
#define SERAPH_NORECOIL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_norecoil_pat[];
extern const UINT8 k_norecoil_mask[];

void NoRecoil_SetPreScanResult(UINT64 va);
void NoRecoil_OnAttach(void);
BOOL NoRecoil_IsReady(void);
BOOL NoRecoil_IsEnabled(void);
void NoRecoil_SetEnabled(BOOL state);
void NoRecoil_OnDetach(void);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_NORECOIL_H */
