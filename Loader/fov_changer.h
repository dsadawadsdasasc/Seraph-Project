#ifndef FOV_CHANGER_H
#define FOV_CHANGER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_fov_pat[];
extern const UINT8 k_fov_mask[];

void FovChanger_SetPreScanResult(UINT64 va);
void FovChanger_OnAttach(void);
void FovChanger_OnDetach(void);

void FovChanger_SetEnabled(BOOL state);
BOOL FovChanger_IsEnabled(void);

void FovChanger_SetValue(float fovVal);
float FovChanger_GetValue(void);

void FovChanger_Tick(void);

#ifdef __cplusplus
}
#endif

#endif /* FOV_CHANGER_H */
