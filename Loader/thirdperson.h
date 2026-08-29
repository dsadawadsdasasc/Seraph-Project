#ifndef THIRDPERSON_H
#define THIRDPERSON_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void ThirdPerson_SetPreScanResult(UINT64 va);
void ThirdPerson_OnAttach(void);
void ThirdPerson_OnDetach(void);
void ThirdPerson_SetEnabled(BOOL state);
BOOL ThirdPerson_IsEnabled(void);
BOOL ThirdPerson_IsReady(void);
void ThirdPerson_SetDistance(float val);
float ThirdPerson_GetDistance(void);

#ifdef __cplusplus
}
#endif

#endif // THIRDPERSON_H
