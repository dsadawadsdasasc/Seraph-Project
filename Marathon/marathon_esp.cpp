#include "marathon_game.h"
#include <windows.h>
#include <d2d1.h>
#include <vector>
#include <string>
#include <cmath>

// Importar variaveis de controle da GUI do Seraph (extern do gui_core.cpp)
extern bool                   g_espActive;
extern bool                   g_espTeamCheck;
extern bool                   g_aimbotActive;
extern int                    g_aimbotSmooth;
extern bool                   g_aimbotShowFov;
extern int                    g_aimbotFovSize;
extern bool                   g_aimbotHeadTarget;
extern bool                   g_aimbotTeamCheck;
extern int                    g_aimbotHotkey;

// Render targets e brushes do esp_overlay.cpp
extern ID2D1HwndRenderTarget* g_espRT;
extern ID2D1SolidColorBrush*  g_espBrushEnemy;
extern ID2D1SolidColorBrush*  g_espBrushAlly;
extern ID2D1SolidColorBrush*  g_espBrushFov;
extern ID2D1SolidColorBrush*  g_espBrushOutline;
extern ID2D1SolidColorBrush*  g_espBrushHpBg;
extern ID2D1SolidColorBrush*  g_espBrushHpDynamic;
extern ID2D1SolidColorBrush*  g_espBrushShDynamic;
extern IDWriteTextFormat*     g_espTF;

// Aimbot state
static float s_accX = 0.0f;
static float s_accY = 0.0f;
static UINT64 s_lockedTarget = 0;

/* Stealth: resolve SendInput dynamically — keeps it out of the PE import
 * table so kernel-level AC scanners cannot flag the binary on load.
 * user32.dll is already mapped in every Win32 process; GetProcAddress has
 * zero overhead after the first call. */
typedef UINT (WINAPI *tSendInput)(UINT, LPINPUT, int);
static tSendInput s_pfnSendInput = NULL;
static void Marathon_MoveMouse(int dx, int dy) {
    if (!s_pfnSendInput) {
        HMODULE hU = GetModuleHandleW(L"user32.dll");
        if (hU) s_pfnSendInput = (tSendInput)(void*)GetProcAddress(hU, "SendInput");
    }
    if (!s_pfnSendInput) return;
    INPUT inp = { 0 };
    inp.type = INPUT_MOUSE;
    inp.mi.dwFlags = MOUSEEVENTF_MOVE;
    inp.mi.dx = (LONG)dx;
    inp.mi.dy = (LONG)dy;
    s_pfnSendInput(1, &inp, sizeof(INPUT));
}


// Tick do aimbot do Marathon
static void Marathon_RunAimbot(float cx, float cy, float screen_w, float screen_h) {
    if (!g_aimbotActive) return;

    // Verificar hotkey do aimbot
    BOOL keyDown = (GetAsyncKeyState(g_aimbotHotkey) & 0x8000) ? TRUE : FALSE;
    if (!keyDown) {
        s_lockedTarget = 0;
        s_accX = 0.0f;
        s_accY = 0.0f;
        return;
    }

    MMatrix4x4 vp;
    if (!Marathon_GetViewProj(&vp)) return;

    float fovR = 25.0f + (g_aimbotFovSize - 1) * 275.0f / 99.0f;
    float fov2 = fovR * fovR;
    UINT32 myTeam = Marathon_GetLocalTeam();

    const auto& players = Marathon_GetPlayers();
    int bestIdx = -1;
    float bestD2 = fov2;

    for (size_t i = 0; i < players.size(); i++) {
        const auto& p = players[i];
        if (p.isLocal) continue;
        if (g_aimbotTeamCheck && p.teamId == myTeam) continue;

        MVector3 targetPos = g_aimbotHeadTarget ? p.headPos : p.basePosHigh;
        // Ajuste se nao for head
        if (!g_aimbotHeadTarget) {
            targetPos.z -= 0.20f;
        }

        MVector2 screenPos{};
        if (!Marathon_WorldToScreen(targetPos, screenPos, vp, screen_w, screen_h)) continue;

        float dx = screenPos.x - cx;
        float dy = screenPos.y - cy;
        float d2 = dx*dx + dy*dy;
        if (d2 < bestD2) {
            bestD2 = d2;
            bestIdx = (int)i;
        }
    }

    if (bestIdx < 0) return;

    const auto& target = players[bestIdx];
    MVector3 aimPos = g_aimbotHeadTarget ? target.headPos : target.basePosHigh;
    if (!g_aimbotHeadTarget) {
        aimPos.z -= 0.20f;
    }

    MVector2 screenAim{};
    if (!Marathon_WorldToScreen(aimPos, screenAim, vp, screen_w, screen_h)) return;

    float dx = screenAim.x - cx;
    float dy = screenAim.y - cy;

    float t = (float)(g_aimbotSmooth - 1) / 99.0f;
    float smooth = 1.0f + 35.0f * (t * t);
    s_accX += dx / smooth;
    s_accY += dy / smooth;

    int mx = (int)s_accX;
    int my = (int)s_accY;
    s_accX -= (float)mx;
    s_accY -= (float)my;

    if (mx != 0 || my != 0) {
        Marathon_MoveMouse(mx, my);
    }
}

// Renderizar o ESP
void Marathon_RenderESP(float screen_w, float screen_h) {
    if (!g_espRT) return;

    float cx = screen_w * 0.5f;
    float cy = screen_h * 0.5f;

    // Aimbot FOV
    if (g_aimbotActive && g_aimbotShowFov && g_espBrushFov) {
        float fovR = 25.0f + (g_aimbotFovSize - 1) * 275.0f / 99.0f;
        g_espRT->DrawEllipse(D2D1::Ellipse({ cx, cy }, fovR, fovR), g_espBrushFov, 1.0f);
    }

    if (!g_espActive) return;

    MMatrix4x4 vp;
    if (!Marathon_GetViewProj(&vp)) return;

    UINT32 myTeam = Marathon_GetLocalTeam();
    const auto& players = Marathon_GetPlayers();

    for (const auto& p : players) {
        if (p.isLocal) continue;
        if (g_espTeamCheck && p.teamId == myTeam) continue;

        MVector2 screenBottom{}, screenTop{};
        if (!Marathon_WorldToScreen(p.basePosLow, screenBottom, vp, screen_w, screen_h)) continue;
        if (!Marathon_WorldToScreen(p.basePosHigh, screenTop, vp, screen_w, screen_h)) continue;

        float boxHeight = std::abs(screenBottom.y - screenTop.y);
        float boxWidth = boxHeight * 0.55f;

        float l = screenTop.x - (boxWidth * 0.5f);
        float t = screenTop.y;
        float r = screenBottom.x + (boxWidth * 0.5f);
        float b = screenBottom.y;

        // Selecionar pincel
        ID2D1SolidColorBrush* br = (p.teamId == myTeam) ? g_espBrushAlly : g_espBrushEnemy;
        if (!br) br = g_espBrushEnemy;

        // 1. Outline preto
        if (g_espBrushOutline) {
            g_espRT->DrawRectangle(D2D1::RectF(l - 1.0f, t - 1.0f, r + 1.0f, b + 1.0f), g_espBrushOutline, 1.0f);
            g_espRT->DrawRectangle(D2D1::RectF(l + 1.0f, t + 1.0f, r - 1.0f, b - 1.0f), g_espBrushOutline, 1.0f);
        }

        // 2. Box Principal
        g_espRT->DrawRectangle(D2D1::RectF(l, t, r, b), br, 1.0f);

        // 3. Head Dot / Circle
        MVector2 screenHead{};
        if (p.headPos.x != 0.0f && Marathon_WorldToScreen(p.headPos, screenHead, vp, screen_w, screen_h)) {
            float rad = boxHeight / 15.0f;
            if (rad < 2.0f) rad = 2.0f;
            if (rad > 10.0f) rad = 10.0f;
            
            if (g_espBrushOutline) {
                g_espRT->DrawEllipse(D2D1::Ellipse({ screenHead.x, screenHead.y }, rad, rad), g_espBrushOutline, 2.0f);
            }
            g_espRT->DrawEllipse(D2D1::Ellipse({ screenHead.x, screenHead.y }, rad, rad), br, 1.0f);
        }
    }

    // Aimbot Tick
    Marathon_RunAimbot(cx, cy, screen_w, screen_h);
}
