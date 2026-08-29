#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void Revive_OnAttach(void);
void Revive_OnDetach(void);
void Revive_SetEnabled(BOOL en);
BOOL Revive_IsEnabled(void);
BOOL Revive_IsReady(void);
void Revive_Tick(void);

#ifdef __cplusplus
}
#endif

