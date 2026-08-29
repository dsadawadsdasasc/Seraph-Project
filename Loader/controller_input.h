#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Virtual key codes assigned for Gamepad/PS5 buttons (0xE0 - 0xED) */
#define VK_PAD_L2       0xE0
#define VK_PAD_R2       0xE1
#define VK_PAD_L1       0xE2
#define VK_PAD_R1       0xE3
#define VK_PAD_L3       0xE4
#define VK_PAD_R3       0xE5
#define VK_PAD_CROSS    0xE6
#define VK_PAD_CIRCLE   0xE7
#define VK_PAD_SQUARE   0xE8
#define VK_PAD_TRIANGLE 0xE9
#define VK_PAD_UP       0xEA
#define VK_PAD_DOWN     0xEB
#define VK_PAD_LEFT     0xEC
#define VK_PAD_RIGHT    0xED

typedef enum {
    PS5_KEY_NONE     = 0,
    PS5_KEY_L2       = VK_PAD_L2,
    PS5_KEY_R2       = VK_PAD_R2,
    PS5_KEY_L1       = VK_PAD_L1,
    PS5_KEY_R1       = VK_PAD_R1,
    PS5_KEY_L3       = VK_PAD_L3,
    PS5_KEY_R3       = VK_PAD_R3,
    PS5_KEY_CROSS    = VK_PAD_CROSS,
    PS5_KEY_CIRCLE   = VK_PAD_CIRCLE,
    PS5_KEY_SQUARE   = VK_PAD_SQUARE,
    PS5_KEY_TRIANGLE = VK_PAD_TRIANGLE,
    PS5_KEY_UP       = VK_PAD_UP,
    PS5_KEY_DOWN     = VK_PAD_DOWN,
    PS5_KEY_LEFT     = VK_PAD_LEFT,
    PS5_KEY_RIGHT    = VK_PAD_RIGHT
} PS5ControllerKey;

void ControllerInput_Init(void);
void ControllerInput_Shutdown(void);
BOOL ControllerInput_IsKeyPressed(int key);
int  ControllerInput_GetAnyPressedKey(void);
const wchar_t* ControllerInput_GetKeyName(int key);

#ifdef __cplusplus
}
#endif
