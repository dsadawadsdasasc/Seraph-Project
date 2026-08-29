#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Instantly teleports the local player to Y=-700 (below map floor → death). */
void Suicide_Trigger(void);

/* Runtime hotkey (polled by gui.c WM_KEYDOWN / WM_MBUTTONDOWN). */
void Suicide_SetHotkey(int vk);
int  Suicide_GetHotkey(void);

#ifdef __cplusplus
}
#endif
