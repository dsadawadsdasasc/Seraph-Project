#pragma once
/* aimbot.h — Screen-space proportional mouse aimbot */

#include <windows.h>
#include "esp.h"
#include "skeleton.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AIMBOT_KEY            VK_RBUTTON
#define AIMBOT_FOV_PX_DEFAULT 100.0f
#define AIMBOT_TARGET_UNKNOWN 1

/* Call once per render frame after ESP_GetEntityBoxes().
 * Does nothing when AIMBOT_KEY is not held or aimbot is disabled.
 * Skips team==0 (allies) when team-check is enabled. */
void Aimbot_Tick(const EspBox *boxes, int n, int screen_w, int screen_h,
                 const SkelEntity *skel, int ns);

void  Aimbot_SetEnabled(BOOL enable);
void  Aimbot_SetSmooth(int val_1_100);      /* 1=snap, 100=smooth */
void  Aimbot_SetKey(int vk);
void  Aimbot_SetFovSize(int val_1_100);     /* 1-100 → 25-300 px */
void  Aimbot_SetShowFov(BOOL show);
void  Aimbot_SetTargetHead(BOOL head);
void  Aimbot_SetSwitchDelay(float sec);
void  Aimbot_SetTeamCheck(BOOL check);

void  Aimbot_SetControllerKey(int key);
int   Aimbot_GetControllerKey(void);

BOOL  Aimbot_GetShowFov(void);
float Aimbot_GetFovPx(void);
BOOL  Aimbot_IsTargetHead(void);

void Aimbot_SetMemoryAim(BOOL enable);
BOOL Aimbot_IsMemoryAim(void);

void Aimbot_SetTriggerbot(BOOL enable);
BOOL Aimbot_IsTriggerbot(void);

#ifdef __cplusplus
}
#endif
