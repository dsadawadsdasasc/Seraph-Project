#pragma once
#include <windows.h>
#ifdef __cplusplus
#include <d3d12.h>
#include <dxgi1_4.h>
#include <d3dcompiler.h>
#include <dwrite.h>
#include <d2d1.h>
#include <d2d1_1.h>
#pragma comment(lib,"d3d12.lib")
#pragma comment(lib,"dxgi.lib")
#pragma comment(lib,"d3dcompiler.lib")
#pragma comment(lib,"dwrite.lib")
#pragma comment(lib,"d2d1.lib")
#endif
/* class DX12Overlay — definida em d2d_engine.h. NÃO redefinir aqui. */

#ifdef __cplusplus
extern "C" {
#endif
    BOOL Overlay_Create(HWND hWnd);
    /* Starts attach + FIT in background. Safe to call multiple times.
     * Should only be called AFTER login succeeds and BYOVD is ready. */
    void Overlay_StartFeatureInit(void);
    /* Returns TRUE once FeatureInitThread has completed at least once. */
    BOOL Overlay_IsFeatureInitDone(void);
    void Overlay_RenderMenu();
    void Overlay_RenderSystemCheck();
    void Overlay_RenderLogin();
    void Overlay_RenderLoading(const wchar_t* text);
    void Overlay_SetSystemCheckResults(BOOL ts, BOOL sb, BOOL hvci);
    void Overlay_Destroy();
    void Overlay_UpdateMouse(int x, int y, BOOL leftDown);
    void Overlay_UpdateRightMouse(int x, int y, BOOL rightDown);
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
    void Overlay_SetStreamProofWindow(HWND hWnd, BOOL enable);
    void Overlay_LoadConfigSettings(void);
    void Overlay_SaveConfig(void);
    void Overlay_RebuildDevTab(void);
    int  Overlay_GetMenuHotkey(void);
    void Overlay_SetMenuHotkey(int vk);
    BOOL Overlay_IsWaitingForKey(void);
    void Overlay_SetWaitingForKey(BOOL waiting);
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
    int  Overlay_LoginGetFocus(void);
    void Overlay_AddNotification(const wchar_t* header, const wchar_t* body);
    void Overlay_AddNotificationEx(const wchar_t* header, const wchar_t* body, float durSec);
    void Overlay_NumInputChar(wchar_t c);
    void Overlay_NumInputBackspace(void);
    BOOL Overlay_IsNumInputFocused(void);
    void Overlay_NumInputDefocus(void);
    void Overlay_FlyToggle(void);
    BOOL Overlay_IsTextInputFocused(void);
    void Overlay_TextInputChar(wchar_t c);
    void Overlay_TextInputBackspace(void);
    void Overlay_TextInputDefocus(void);
    BOOL Overlay_IsWaitingForTpKey(void);
    int  Overlay_GetTpWaitingSlot(void);
    void Overlay_SetTpHotkey(int vk);
    int   Overlay_GetOpkHotkey(void);
    void  Overlay_SetOpkHotkey(int vk);
    BOOL  Overlay_IsWaitingForOpkKey(void);
    void  Overlay_OpkToggle(void);
#ifdef __cplusplus
}
#endif
