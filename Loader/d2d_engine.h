#pragma once
#include <windows.h>
#ifdef __cplusplus
#include <dwrite.h>
#include <d2d1.h>
#pragma comment(lib,"dwrite.lib")
#pragma comment(lib,"d2d1.lib")
#endif

/* D2D Engine — motor Direct2D puro compartilhado entre Stub.exe e svc.dll.
 *
 * Contém: criação/destruição de recursos D2D+DWrite, RenderLogin,
 * RenderSystemCheck, RenderLoading, login state, stream-proof, config I/O
 * básico (hotkeys + stream-proof toggle), DrawEmblem, notificações.
 *
 * NÃO contém: feature toggles, AOB scans, byovd.h, fly.h, etc.
 * Esses ficam em gui_core.cpp (svc.dll only). */

#ifdef __cplusplus
class DX12Overlay {
public:
    static bool Create(HWND hWnd);
    static void Destroy();
    static void RenderLogin();
    static void RenderSystemCheck();
    static void RenderLoading(const wchar_t* text);
    static void RenderMenu();                        /* impl em gui_core.cpp */
    static void SetSystemCheckResults(bool ts, bool sb, bool hvci);
    static void UpdateMouse(int x, int y, bool leftDown);
    static void UpdateRightMouse(int x, int y, bool rightDown);
    static void SetMenuVisible(bool visible);
    static bool IsMenuVisible();
    static int  GetActiveTab();
    static void SetActiveTab(int tab);
    static void Stop();
    static bool IsRunning();
};
extern ID2D1SolidColorBrush* g_scratchBr;
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif

    BOOL  Overlay_Create(HWND hWnd);
    void  Overlay_Destroy(void);
    void  Overlay_Stop(void);
    BOOL  Overlay_IsRunning(void);

    void  Overlay_UpdateMouse(int x, int y, BOOL leftDown);
    void  Overlay_SetMenuVisible(BOOL visible);      /* impl em gui_core.cpp — wrapper de SetMenuVisible */
    void  Overlay_SetSystemCheckResults(BOOL ts, BOOL sb, BOOL hvci);

    void  Overlay_RenderLogin(void);
    void  Overlay_RenderSystemCheck(void);
    void  Overlay_RenderLoading(const wchar_t* text);
    /* Overlay_RenderMenu — declarada mas implementada em gui_core.cpp */
    void  Overlay_RenderMenu(void);

    /* Login state */
    void  Overlay_LoginChar(wchar_t c);
    void  Overlay_LoginBackspace(void);
    void  Overlay_LoginSetFocus(int field);
    void  Overlay_LoginToggleFocus(void);
    void  Overlay_LoginClick(void);
    BOOL  Overlay_LoginWasClicked(void);
    void  Overlay_LoginShowError(void);
    void  Overlay_LoginShowErrorMsg(const wchar_t* msg);
    void  Overlay_LoginShowStatusMsg(const wchar_t* msg);
    void  Overlay_LoginSetCreds(const wchar_t* user, const wchar_t* key);
    void  Overlay_LoginGetCreds(wchar_t* user, int uMax, wchar_t* key, int kMax);
    int   Overlay_LoginGetFocus(void);

    /* Notifications */
    void  Overlay_AddNotification(const wchar_t* header, const wchar_t* body);
    void  Overlay_AddNotificationEx(const wchar_t* header, const wchar_t* body, float durSec);

    /* Stream proof + config */
    void  Overlay_SetStreamProofWindow(HWND hWnd, BOOL enable);
    void  Overlay_LoadConfigSettings(void);
    void  Overlay_SaveConfig(void);

    /* Brush cache: call after render target creation or D2DERR_RECREATE_TARGET */
    void  D2DEngine_RecreateBrushes(void);

    /* Config hotkey accessors (lidos por gui.c no processamento de hotkeys) */
    int   Overlay_GetMenuHotkey(void);
    int   Overlay_GetFlyHotkey(void);
    int   Overlay_GetFlyDirHotkey(void);
    int   Overlay_GetGsHotkey(void);
    int   Overlay_GetAimbotHotkey(void);
    int   Overlay_GetAimbotTargetHeadHotkey(void);
    int   Overlay_GetSuicideHotkey(void);
    int   Overlay_GetFuserHotkey(void);
    int   Overlay_GetOpkHotkey(void);

#ifdef __cplusplus
}
#endif
