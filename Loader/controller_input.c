/* controller_input.c — Dual XInput + WinMM Gamepad detection for PS5 (DualSense) & PC controllers */
#include "controller_input.h"
#include "debug.h"
#include "xor_strings.h"
#include "XorStr.h"
#include <windows.h>
#include <mmsystem.h>

/* XInput types */
typedef struct {
    WORD wButtons;
    BYTE bLeftTrigger;
    BYTE bRightTrigger;
    SHORT sThumbLX;
    SHORT sThumbLY;
    SHORT sThumbRX;
    SHORT sThumbRY;
} XINPUT_GAMEPAD_EX;

typedef struct {
    DWORD dwPacketNumber;
    XINPUT_GAMEPAD_EX Gamepad;
} XINPUT_STATE_EX;

typedef DWORD (WINAPI *PFN_XInputGetState)(DWORD dwUserIndex, XINPUT_STATE_EX* pState);

/* WinMM function pointer type */
typedef MMRESULT (WINAPI *PFN_joyGetPosEx)(UINT uJoyID, LPJOYINFOEX pji);

static HMODULE s_hXInput = NULL;
static PFN_XInputGetState s_pfnXInputGetState = NULL;

static HMODULE s_hWinMM = NULL;
static PFN_joyGetPosEx s_pfnJoyGetPosEx = NULL;

static BOOL s_initialized = FALSE;

static DWORD s_lastCheck[4] = {0, 0, 0, 0};
static BOOL  s_slotConnected[4] = {FALSE, FALSE, FALSE, FALSE};

void ControllerInput_Init(void)
{
    if (s_initialized) return;
    s_initialized = TRUE;

    /* Load XInput */
    int i;
    for (i = 0; i < 3; i++) {
        const char* dllName = (i == 0) ? DXOR_A(ENC_xinput1_4_dll) :
                              (i == 1) ? DXOR_A(ENC_xinput1_3_dll) :
                                         DXOR_A(ENC_xinput9_1_0_dll);
        s_hXInput = LoadLibraryA(dllName);
        if (s_hXInput) {
            s_pfnXInputGetState = (PFN_XInputGetState)GetProcAddress(s_hXInput, DXOR_A(ENC_XInputGetState));
            if (s_pfnXInputGetState) break;
            FreeLibrary(s_hXInput);
            s_hXInput = NULL;
        }
    }

    /* Load WinMM */
    s_hWinMM = LoadLibraryW(DXOR_W(ENC_winmm_dll));
    if (s_hWinMM) {
        s_pfnJoyGetPosEx = (PFN_joyGetPosEx)GetProcAddress(s_hWinMM, DXOR_A(ENC_joyGetPosEx));
    }
}

void ControllerInput_Shutdown(void)
{
    if (s_hXInput) {
        FreeLibrary(s_hXInput);
        s_hXInput = NULL;
    }
    if (s_hWinMM) {
        FreeLibrary(s_hWinMM);
        s_hWinMM = NULL;
    }
    s_pfnXInputGetState = NULL;
    s_pfnJoyGetPosEx = NULL;
    s_initialized = FALSE;
}

static BOOL _CheckXInputKey(int key, const XINPUT_GAMEPAD_EX* g)
{
    switch (key) {
        case VK_PAD_L2:       return g->bLeftTrigger > 30;
        case VK_PAD_R2:       return g->bRightTrigger > 30;
        case VK_PAD_L1:       return (g->wButtons & 0x0100) != 0;
        case VK_PAD_R1:       return (g->wButtons & 0x0200) != 0;
        case VK_PAD_L3:       return (g->wButtons & 0x0040) != 0;
        case VK_PAD_R3:       return (g->wButtons & 0x0080) != 0;
        case VK_PAD_CROSS:    return (g->wButtons & 0x4000) != 0;
        case VK_PAD_CIRCLE:   return (g->wButtons & 0x2000) != 0;
        case VK_PAD_SQUARE:   return (g->wButtons & 0x1000) != 0;
        case VK_PAD_TRIANGLE: return (g->wButtons & 0x8000) != 0;
        case VK_PAD_UP:       return (g->wButtons & 0x0001) != 0;
        case VK_PAD_DOWN:     return (g->wButtons & 0x0002) != 0;
        case VK_PAD_LEFT:     return (g->wButtons & 0x0004) != 0;
        case VK_PAD_RIGHT:    return (g->wButtons & 0x0008) != 0;
        default: return FALSE;
    }
}

static BOOL _CheckWinMMKey(int key, const JOYINFOEX* j)
{
    switch (key) {
        case VK_PAD_L2:
            return ((j->dwButtons & (1 << 6)) != 0) || (j->dwZpos > 40000) || (j->dwVpos > 40000);
        case VK_PAD_R2:
            return ((j->dwButtons & (1 << 7)) != 0) || (j->dwRpos > 40000);
        case VK_PAD_L1:       return (j->dwButtons & (1 << 4)) != 0;
        case VK_PAD_R1:       return (j->dwButtons & (1 << 5)) != 0;
        case VK_PAD_L3:       return (j->dwButtons & (1 << 10)) != 0;
        case VK_PAD_R3:       return (j->dwButtons & (1 << 11)) != 0;
        case VK_PAD_CROSS:    return (j->dwButtons & (1 << 1)) != 0 || (j->dwButtons & (1 << 0)) != 0;
        case VK_PAD_CIRCLE:   return (j->dwButtons & (1 << 2)) != 0;
        case VK_PAD_SQUARE:   return (j->dwButtons & (1 << 0)) != 0 || (j->dwButtons & (1 << 3)) != 0;
        case VK_PAD_TRIANGLE: return (j->dwButtons & (1 << 3)) != 0;
        case VK_PAD_UP:       return j->dwPOV == 0;
        case VK_PAD_RIGHT:    return j->dwPOV == 9000;
        case VK_PAD_DOWN:     return j->dwPOV == 18000;
        case VK_PAD_LEFT:     return j->dwPOV == 27000;
        default: return FALSE;
    }
}

BOOL ControllerInput_IsKeyPressed(int key)
{
    if (key < VK_PAD_L2 || key > VK_PAD_RIGHT) return FALSE;
    if (!s_initialized) ControllerInput_Init();

    DWORD now = GetTickCount();

    /* 1. Try XInput */
    BOOL xinputFound = FALSE;
    if (s_pfnXInputGetState) {
        DWORD i;
        for (i = 0; i < 4; i++) {
            /* Throttle reconnect checks for empty slots (1000ms) to avoid CPU overhead, 
             * but read active slots immediately at full polling speed. */
            if (!s_slotConnected[i] && (now - s_lastCheck[i] < 1000)) continue;
            
            XINPUT_STATE_EX state;
            ZeroMemory(&state, sizeof(state));
            if (s_pfnXInputGetState(i, &state) == 0) {
                s_slotConnected[i] = TRUE;
                xinputFound = TRUE;
                if (_CheckXInputKey(key, &state.Gamepad)) return TRUE;
            } else {
                s_lastCheck[i] = now; /* Record failure timestamp */
                s_slotConnected[i] = FALSE;
            }
        }
    }

    /* 2. Try WinMM Joystick API for native PS5 controllers (only if XInput didn't find anything) */
    if (!xinputFound && s_pfnJoyGetPosEx) {
        static DWORD lastWinMMCheck = 0;
        static BOOL winmmConnected = FALSE;
        /* Throttle WinMM connection check if it was not connected recently */
        if (winmmConnected || (now - lastWinMMCheck >= 2000)) {
            if (!winmmConnected) lastWinMMCheck = now;
            UINT id;
            BOOL anyFound = FALSE;
            for (id = 0; id < 4; id++) {
                JOYINFOEX ji;
                ZeroMemory(&ji, sizeof(ji));
                ji.dwSize = sizeof(ji);
                ji.dwFlags = JOY_RETURNALL;
                if (s_pfnJoyGetPosEx(id, &ji) == 0) {
                    anyFound = TRUE;
                    if (_CheckWinMMKey(key, &ji)) {
                        winmmConnected = TRUE;
                        return TRUE;
                    }
                }
            }
            winmmConnected = anyFound;
        }
    }

    return FALSE;
}

int ControllerInput_GetAnyPressedKey(void)
{
    int keys[] = {
        VK_PAD_L2, VK_PAD_R2, VK_PAD_L1, VK_PAD_R1,
        VK_PAD_L3, VK_PAD_R3, VK_PAD_CROSS, VK_PAD_CIRCLE,
        VK_PAD_SQUARE, VK_PAD_TRIANGLE, VK_PAD_UP, VK_PAD_DOWN,
        VK_PAD_LEFT, VK_PAD_RIGHT
    };
    int i;
    for (i = 0; i < 14; i++) {
        if (ControllerInput_IsKeyPressed(keys[i])) return keys[i];
    }
    return 0;
}

const wchar_t* ControllerInput_GetKeyName(int key)
{
    switch (key) {
        case VK_PAD_L2:       return L"L2 (PS5)";
        case VK_PAD_R2:       return L"R2 (PS5)";
        case VK_PAD_L1:       return L"L1 (PS5)";
        case VK_PAD_R1:       return L"R1 (PS5)";
        case VK_PAD_L3:       return L"L3 (PS5)";
        case VK_PAD_R3:       return L"R3 (PS5)";
        case VK_PAD_CROSS:    return L"Cross (PS5)";
        case VK_PAD_CIRCLE:   return L"Circle (PS5)";
        case VK_PAD_SQUARE:   return L"Square (PS5)";
        case VK_PAD_TRIANGLE: return L"Triangle (PS5)";
        case VK_PAD_UP:       return L"D-Pad Up (PS5)";
        case VK_PAD_DOWN:     return L"D-Pad Down (PS5)";
        case VK_PAD_LEFT:     return L"D-Pad Left (PS5)";
        case VK_PAD_RIGHT:    return L"D-Pad Right (PS5)";
        default:              return L"Controller Key";
    }
}
