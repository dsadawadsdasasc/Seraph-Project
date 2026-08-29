#ifndef SERAPH_DMA_BUILD
#ifndef NDEBUG
#include "bunnyhop.h"
#include "fly.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include <math.h>
#include "syscalls.h"  /* SysNtUserGetAsyncKeyState */

static BOOL  s_enabled = FALSE;
static float s_bhopSpeed = 20.0f;
static float s_bhopVertical = 10.0f;

void BunnyHop_SetEnabled(BOOL state) {
    s_enabled = state;
}

BOOL BunnyHop_IsEnabled(void) {
    return s_enabled;
}

void BunnyHop_SetSpeed(float speed) {
    s_bhopSpeed = speed;
}

void BunnyHop_SetVertical(float vertical) {
    s_bhopVertical = vertical;
}

void BunnyHop_Tick(void) {
    if (!s_enabled) return;

    static BOOL wasPressed = FALSE;
    BOOL isPressed = (SysNtUserGetAsyncKeyState(VK_SPACE) & 0x8000) != 0;

    if (isPressed && !wasPressed) {
        UINT64 playerBase = Fly_GetLpEp();
        if (playerBase) {
            UINT64 cr3 = GetDestiny2CR3();
            if (cr3) {
                float cY = 1.0f, sY = 0.0f, cP = 1.0f, sP = 0.0f;
                Fly_GetCamTrig(&cY, &sY, &cP, &sP);

                float fwd_x = cP * cY;
                float fwd_y = cP * sY;
                
                float fMag = sqrtf(fwd_x * fwd_x + fwd_y * fwd_y);
                if (fMag < 1e-6f) { fwd_x = 1.0f; fwd_y = 0.0f; fMag = 1.0f; }
                fwd_x /= fMag;
                fwd_y /= fMag;

                float right_x = -fwd_y;
                float right_y = fwd_x;

                float inputF = 0.0f;
                float inputR = 0.0f;

                if (SysNtUserGetAsyncKeyState('W') & 0x8000) inputF += 1.0f;
                if (SysNtUserGetAsyncKeyState('S') & 0x8000) inputF -= 1.0f;
                if (SysNtUserGetAsyncKeyState('D') & 0x8000) inputR -= 1.0f;
                if (SysNtUserGetAsyncKeyState('A') & 0x8000) inputR += 1.0f;

                float dir_x = 0.0f, dir_y = 0.0f;
                if (fabsf(inputF) < 0.1f && fabsf(inputR) < 0.1f) {
                    dir_x = fwd_x;
                    dir_y = fwd_y;
                } else {
                    dir_x = fwd_x * inputF + right_x * inputR;
                    dir_y = fwd_y * inputF + right_y * inputR;
                    float dMag = sqrtf(dir_x * dir_x + dir_y * dir_y);
                    if (dMag > 1e-6f) { dir_x /= dMag; dir_y /= dMag; }
                }

                float finalVel[3];
                finalVel[0] = dir_x * s_bhopSpeed;
                finalVel[1] = dir_y * s_bhopSpeed;
                finalVel[2] = s_bhopVertical;

                if (BYOVD_TRYLOCK()) {
                    BYOVD_WriteVA_Fresh(cr3, playerBase + 0x230u, finalVel, sizeof(finalVel));
                    BYOVD_UNLOCK();
                }
            }
        }
    }
    wasPressed = isPressed;
}
#endif
#endif