#pragma once
#include <windows.h>
#include "gui_core.h"
#include "evasion_user.h"
struct _LOADER_CTX;
typedef struct _LOADER_CTX LOADER_CTX;

#ifdef __cplusplus
extern "C" {
#endif
void ToggleMenu();
void __cdecl Overlay_SetMenuVisible(BOOL v);
BOOL IsMenuVisible();

// EXPORTED UI WRAPPERS
BOOL Overlay_Create(HWND hWnd);
void Overlay_RenderMenu();
void Overlay_RenderSystemCheck();
void Overlay_RenderLogin();
void Overlay_RenderLoading(const wchar_t* text);
void Overlay_SetSystemCheckResults(BOOL ts, BOOL sb, BOOL hvci);
void Overlay_Destroy();
void Overlay_UpdateMouse(int x, int y, BOOL leftDown);
void Overlay_Stop();
BOOL Overlay_IsRunning();
void Overlay_LoginChar(wchar_t c);
void Overlay_LoginBackspace(void);
void Overlay_LoginSetFocus(int field);
void Overlay_LoginToggleFocus(void);
void Overlay_LoginClick(void);
BOOL Overlay_LoginWasClicked(void);
void Overlay_LoginShowError(void);
void Overlay_LoginShowErrorMsg(const wchar_t* msg);
void Overlay_LoginShowStatusMsg(const wchar_t* msg);
void Overlay_LoginSetCreds(const wchar_t* user, const wchar_t* key);
void Overlay_LoginGetCreds(wchar_t* user, int uMax, wchar_t* key, int kMax);
int  Overlay_LoginGetFocus(void);
void Overlay_SetStreamProofWindow(HWND hWnd, BOOL enable);
void Overlay_LoadConfigSettings(void);
void Overlay_SaveConfig(void);
void Overlay_RebuildDevTab(void);
void Overlay_AddNotification(const wchar_t *header, const wchar_t *body);
int  Overlay_GetMenuHotkey(void);
void Overlay_SetMenuHotkey(int vk);
BOOL Overlay_IsWaitingForKey(void);
int  Overlay_GetFlyHotkey(void);
void Overlay_SetFlyHotkey(int vk);
BOOL Overlay_IsWaitingForFlyKey(void);
int  Overlay_GetFlyDirHotkey(void);
void Overlay_SetFlyDirHotkey(int vk);
BOOL Overlay_IsWaitingForFlyDirKey(void);
void Overlay_FlyDirToggle(void);
int  Overlay_GetGsHotkey(void);
void Overlay_SetGsHotkey(int vk);
BOOL Overlay_IsWaitingForGsKey(void);
void Overlay_GameSpeedToggle(void);
int  Overlay_GetAimbotHotkey(void);
void Overlay_SetAimbotHotkey(int vk);
BOOL Overlay_IsWaitingForAimbotKey(void);
int  Overlay_GetAimbotTargetHeadHotkey(void);
void Overlay_SetAimbotTargetHeadHotkey(int vk);
BOOL Overlay_IsWaitingForAimbotTargetHeadKey(void);
void Overlay_AimbotTargetHeadToggle(void);
int  Overlay_GetSuicideHotkey(void);
void Overlay_SetSuicideHotkey(int vk);
BOOL Overlay_IsWaitingForSuicideKey(void);
int  Overlay_GetFuserHotkey(void);
void Overlay_SetFuserHotkey(int vk);
BOOL Overlay_IsWaitingForFuserKey(void);
int  Overlay_GetOpkHotkey(void);
void Overlay_SetOpkHotkey(int vk);
BOOL Overlay_IsWaitingForOpkKey(void);
void Overlay_OpkToggle(void);
void Overlay_Scroll(int delta);
#ifdef __cplusplus
}
#endif
