/* aimbot.c — Screen-space proportional mouse controller */
#include "aimbot.h"
#include "esp.h"
#include "skeleton.h"
#include "controller_input.h"
#include <math.h>
#include "fly.h"
#include "lists.h"
#include "syscalls.h"  /* SysNtUserGetAsyncKeyState, SysNtUserSendInput */

#ifdef SERAPH_DMA_BUILD
#include "seraph_kmbox.h"
#include "byovd.h"
#include "attach.h"
#endif

/* Runtime config */
static BOOL  s_enabled                 = FALSE;
static float s_smooth                  = 7.0f;
static float s_memSmooth               = 7.0f;
static int   s_activationKey           = VK_RBUTTON;
static int   s_controllerActivationKey = PS5_KEY_L2;
static float s_fovPx                   = AIMBOT_FOV_PX_DEFAULT;
static BOOL  s_showFov       = FALSE;
static BOOL  s_targetHead    = TRUE;
static BOOL  s_teamCheck     = FALSE;
static float s_switchDelay   = 0.0f;

/* Target lock: stores slotIndex+1 so that 0 unambiguously means "no lock" */
static UINT64 s_lockedTarget    = 0;
static BOOL   s_keyPrevDown     = FALSE;
static BOOL   s_waitingRetarget = FALSE;
static DWORD  s_switchWaitSince = 0;

/* Sub-pixel mouse motion accumulators to prevent max-smooth jitter */
static float  s_accX            = 0.0f;
static float  s_accY            = 0.0f;

static BOOL  s_memoryAim = FALSE;
static BOOL  s_triggerbot = FALSE;
static float s_triggerbotTol = 4.0f; /* 4 pixels tolerance */

static void _shoot_click(BOOL down)
{
    static BOOL s_clickState = FALSE;
    if (s_clickState == down) return; /* Avoid redundant input events */
    s_clickState = down;

#ifdef SERAPH_DMA_BUILD
    if (SeraphKmbox_IsReady()) {
        extern void SeraphKmbox_LeftClick(int isdown);
        SeraphKmbox_LeftClick(down ? 1 : 0);
        return;
    }
#endif

    INPUT inp      = {0};
    inp.type       = INPUT_MOUSE;
    inp.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
    SysNtUserSendInput(1, &inp, sizeof(INPUT));
}

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static float _normalize_angle(float a)
{
    a = fmodf(a + (float)M_PI, 2.0f * (float)M_PI);
    if (a < 0.0f) a += 2.0f * (float)M_PI;
    return a - (float)M_PI;
}

static BOOL _apply_memory_aim(float tx, float ty, float tz, float camX, float camY, float camZ)
{
    float dx = tx - camX;
    float dy = ty - camY;
    float dz = tz - camZ;
    float horiz = sqrtf(dx*dx + dy*dy);
    if (horiz < 0.05f) return FALSE;
    float wantYaw   = atan2f(dy, dx);
    float wantPitch = atan2f(-dz, horiz);
    float curYaw = 0.0f, curPitch = 0.0f;
    if (!Fly_ReadCam(&curYaw, &curPitch, NULL)) return FALSE;
    float dyaw   = _normalize_angle(wantYaw - curYaw);
    float dpitch = wantPitch - curPitch;

    /* Instant rage snap (0-frame/instant lock) when s_memSmooth is at minimum (1.0) */
    if (s_memSmooth <= 1.01f) {
        return Fly_WriteCam(wantYaw, wantPitch);
    }
    return Fly_WriteCam(curYaw + dyaw / s_memSmooth, curPitch + dpitch / s_memSmooth);
}

void Aimbot_SetMemoryAim(BOOL enable) { 
    s_memoryAim = enable; 
    if (enable) {
        UINT64 cr3 = GetDestiny2CR3();
        UINT64 d2Base = GetDestiny2Base();
        if (cr3 && d2Base) {
            /* Declare the watchdog verify and reinstall function from fly.c locally */
            extern BOOL Fly_RestoreCamHookOnDemand(UINT64 cr3, UINT64 d2Base);
            Fly_RestoreCamHookOnDemand(cr3, d2Base);
        }
    }
    if (!enable && !s_enabled && !s_triggerbot) {
        _shoot_click(FALSE);
    }
}
BOOL Aimbot_IsMemoryAim(void)         { return s_memoryAim; }

void Aimbot_SetTriggerbot(BOOL enable) {
    s_triggerbot = enable;
    if (!enable) {
        _shoot_click(FALSE);
    }
}
BOOL Aimbot_IsTriggerbot(void)         { return s_triggerbot; }

/* Setters */
void Aimbot_SetEnabled(BOOL e)
{
    s_enabled = e;
    if (!e && !s_memoryAim && !s_triggerbot) {
        _shoot_click(FALSE);
    }
}
void Aimbot_SetKey(int vk)           { s_activationKey = vk; }
void Aimbot_SetShowFov(BOOL show)    { s_showFov       = show; }
void Aimbot_SetTargetHead(BOOL h)    { s_targetHead    = h; }
void Aimbot_SetTeamCheck(BOOL check) { s_teamCheck     = check; }
void Aimbot_SetSwitchDelay(float s)  { s_switchDelay   = s < 0.0f ? 0.0f : s; }

void Aimbot_SetSmooth(int val_1_100)
{
    if (val_1_100 < 1)   val_1_100 = 1;
    if (val_1_100 > 100) val_1_100 = 100;
    float t = (val_1_100 - 1) / 99.0f;
    /* Quadratic curve: t*t allows extremely fast/rage speeds at lower slider values
     * and smooth transition to legitimate speeds at higher values.
     * Minimum non-memory smoothing is 1.0f (exact 1:1 mouse movement delta, which is instant snap),
     * and minimum memory smoothing is 1.0f.
     */
    s_smooth = 1.0f + 35.0f * (t * t);
    s_memSmooth = 1.0f + 17.0f * (t * t);
}

void Aimbot_SetFovSize(int val_1_100)
{
    if (val_1_100 < 1)   val_1_100 = 1;
    if (val_1_100 > 100) val_1_100 = 100;
    s_fovPx = 25.0f + (val_1_100 - 1) * 275.0f / 99.0f;
}

void Aimbot_SetControllerKey(int key) { s_controllerActivationKey = key; }
int  Aimbot_GetControllerKey(void)     { return s_controllerActivationKey; }

/* Getters */
BOOL  Aimbot_GetShowFov(void)  { return s_showFov;  }
float Aimbot_GetFovPx(void)    { return s_fovPx;    }
BOOL  Aimbot_IsTargetHead(void){ return s_targetHead; }

/*
 * Pick the best aim bone index for a given skeleton entity.
 * Priority: head (18) > chest (14) > upper-spine (11) > highest-Z bone.
 * Returns -1 if no valid bone found.
 */
static int _pick_aim_bone(const SkelEntity *e)
{
    if (s_targetHead) {
        if (e->boneCount > 18 &&
            (e->bones[18].x != 0.0f || e->bones[18].y != 0.0f || e->bones[18].z != 0.0f))
            return 18;
    }
    if (e->boneCount > 14 &&
        (e->bones[14].x != 0.0f || e->bones[14].y != 0.0f || e->bones[14].z != 0.0f))
        return 14;
    if (e->boneCount > 11 &&
        (e->bones[11].x != 0.0f || e->bones[11].y != 0.0f || e->bones[11].z != 0.0f))
        return 11;

    /* Last resort: highest valid bone by world-Z */
    float maxZ = -99999.0f;
    int   best = -1;
    UINT32 k;
    for (k = 0; k < e->boneCount; k++) {
        if (e->bones[k].z > maxZ &&
            (e->bones[k].x != 0.0f || e->bones[k].y != 0.0f || e->bones[k].z != 0.0f)) {
            maxZ = e->bones[k].z;
            best = (int)k;
        }
    }
    return best;
}

void Aimbot_Tick(const EspBox *boxes, int n, int screen_w, int screen_h,
                 const SkelEntity *skel, int ns)
{
    (void)boxes; (void)n; /* boxes unused — targeting is skeleton-based */

    if (screen_w <= 0 || screen_h <= 0) return;
    if (!s_enabled && !s_memoryAim && !s_triggerbot) return;

    BOOL keyDown = FALSE;
    if (s_activationKey >= VK_PAD_L2 && s_activationKey <= VK_PAD_RIGHT) {
        keyDown = ControllerInput_IsKeyPressed(s_activationKey);
    } else {
        keyDown = (SysNtUserGetAsyncKeyState(s_activationKey) & 0x8000) ? TRUE : FALSE;
    }
    if (!keyDown && s_controllerActivationKey > 0) {
        keyDown = ControllerInput_IsKeyPressed(s_controllerActivationKey);
    }
    if (!keyDown) {
        if (s_triggerbot) _shoot_click(FALSE);
        s_lockedTarget    = 0;
        s_keyPrevDown     = FALSE;
        s_waitingRetarget = FALSE;
        s_accX            = 0.0f;
        s_accY            = 0.0f;
        return;
    }
    if (!s_keyPrevDown) {
        s_lockedTarget = 0;
        s_accX         = 0.0f;
        s_accY         = 0.0f;
    }
    s_keyPrevDown = TRUE;

    /* Require cached view/proj matrices for world-to-screen and camera pos */
    float view[16], proj[16];
    BOOL matOk = Skeleton_GetCachedMatrices(view, proj);
    if (!matOk) matOk = ESP_GetCachedMatrices(view, proj);
    if (!matOk) matOk = ESP_ReadMatrices(view, proj);
    if (!matOk) {

        if (s_triggerbot) _shoot_click(FALSE);
        return;
    }

    float camX = -(view[0]*view[12] + view[1]*view[13] + view[2]*view[14]);
    float camY = -(view[4]*view[12] + view[5]*view[13] + view[6]*view[14]);
    float camZ = -(view[8]*view[12] + view[9]*view[13] + view[10]*view[14]);

    float cx   = screen_w * 0.5f;
    float cy   = screen_h * 0.5f;
    float fov2 = s_fovPx  * s_fovPx;

    /* ── Target lock maintenance ──────────────────────────────────────────── */
    int lockedJ = -1;
    if (s_lockedTarget != 0) {
        int j;
        for (j = 0; j < ns; j++) {
            if ((UINT64)skel[j].slotIndex == s_lockedTarget - 1ULL) {
                lockedJ = j;
                break;
            }
        }
        if (lockedJ >= 0) {
            /* Verify locked target is still enemy, alive, and inside FOV circle */
            if (skel[lockedJ].isLocalPlayer || (s_teamCheck && skel[lockedJ].team == 0)) {
                lockedJ = -1;
            } else {
                int aimIdx = _pick_aim_bone(&skel[lockedJ]);
                float sx, sy;
                if (aimIdx >= 0 && ESP_WorldToScreen(view, proj,
                        skel[lockedJ].bones[aimIdx].x,
                        skel[lockedJ].bones[aimIdx].y,
                        skel[lockedJ].bones[aimIdx].z,
                        screen_w, screen_h, &sx, &sy)) {
                    float ddx = sx - cx, ddy = sy - cy;
                    if (ddx*ddx + ddy*ddy > fov2) {
                        lockedJ = -1; /* Locked target moved outside FOV circle */
                    }
                } else {
                    lockedJ = -1;
                }
            }
        }
        if (lockedJ < 0) {
            /* Locked target dropped from snapshot or left FOV — enter switch-delay */
            s_lockedTarget    = 0;
            s_waitingRetarget = TRUE;
            s_switchWaitSince = GetTickCount();
        }
    }

    /* ── Target acquisition ───────────────────────────────────────────────── */
    int bestJ = lockedJ;
    if (bestJ < 0) {
        if (s_waitingRetarget) {
            DWORD elapsed = GetTickCount() - s_switchWaitSince;
            if (elapsed < (DWORD)(s_switchDelay * 1000.0f)) {
                if (s_triggerbot) _shoot_click(FALSE);
                return; /* still in switch-delay window */
            }
        }

        float bestD2 = fov2;
        int j;
        for (j = 0; j < ns; j++) {
            if (skel[j].isLocalPlayer) continue;
            if (s_teamCheck && skel[j].team == 0) continue;

            int aimIdx = _pick_aim_bone(&skel[j]);
            if (aimIdx < 0) continue;

            float sx, sy;
            if (!ESP_WorldToScreen(view, proj,
                    skel[j].bones[aimIdx].x,
                    skel[j].bones[aimIdx].y,
                    skel[j].bones[aimIdx].z,
                    screen_w, screen_h, &sx, &sy))
                continue;

            float ddx = sx - cx, ddy = sy - cy;
            float d2 = ddx*ddx + ddy*ddy;
            if (d2 < bestD2) { bestD2 = d2; bestJ = j; }
        }

        if (bestJ >= 0) {
            s_lockedTarget    = (UINT64)skel[bestJ].slotIndex + 1ULL;
            s_waitingRetarget = FALSE;
        }
    }

    if (bestJ < 0) {
        if (s_triggerbot) _shoot_click(FALSE);
        return;
    }

    /* ── Compute aim point ────────────────────────────────────────────────── */
    int targetIdx = _pick_aim_bone(&skel[bestJ]);
    if (targetIdx < 0) {
        if (s_triggerbot) _shoot_click(FALSE);
        return;
    }

    float bx = skel[bestJ].bones[targetIdx].x;
    float by = skel[bestJ].bones[targetIdx].y;
    float bz = skel[bestJ].bones[targetIdx].z;

    if (!s_targetHead) {
        bz -= 0.20f; /* Mover a mira 20 cm para baixo do peito */
    }

    if (s_memoryAim && _apply_memory_aim(bx, by, bz, camX, camY, camZ)) {
        if (s_triggerbot) {
            float tx, ty;
            if (ESP_WorldToScreen(view, proj, bx, by, bz, screen_w, screen_h, &tx, &ty)) {
                float dx = tx - cx;
                float dy = ty - cy;
                if (sqrtf(dx*dx + dy*dy) <= s_triggerbotTol) {
                    _shoot_click(TRUE);
                } else {
                    _shoot_click(FALSE);
                }
            } else {
                _shoot_click(FALSE);
            }
        }
        return;
    }

    float tx, ty;
    if (!ESP_WorldToScreen(view, proj, bx, by, bz, screen_w, screen_h, &tx, &ty)) {
        if (s_triggerbot) _shoot_click(FALSE);
        return;
    }

    float dx = tx - cx;
    float dy = ty - cy;

    if (s_triggerbot) {
        if (sqrtf(dx*dx + dy*dy) <= s_triggerbotTol) {
            _shoot_click(TRUE);
        } else {
            _shoot_click(FALSE);
        }
    }

    if (s_enabled) {
        s_accX += dx / s_smooth;
        s_accY += dy / s_smooth;
        LONG mx = (LONG)s_accX;
        LONG my = (LONG)s_accY;
        s_accX -= (float)mx;
        s_accY -= (float)my;
        if (mx == 0 && my == 0) return;

#ifdef SERAPH_DMA_BUILD
        if (SeraphKmbox_IsReady()) { SeraphKmbox_MoveAccum((int)mx, (int)my); return; }
#endif

        INPUT inp      = {0};
        inp.type       = INPUT_MOUSE;
        inp.mi.dwFlags = MOUSEEVENTF_MOVE;
        inp.mi.dx      = mx;
        inp.mi.dy      = my;
        SysNtUserSendInput(1, &inp, sizeof(INPUT));
    }
}
