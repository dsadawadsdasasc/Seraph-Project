#include "ThemidaSDK.h"
#include "fly.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "cave_finder.h"
#include "lazyhook.h"
#include "esp.h"
#include "local_player.h"
#include "tigerlist.h"
#include <windows.h>
#include "aob_patterns.h"
#include <math.h>
#include <float.h>
#include <string.h>
#include "controller_input.h"
#include "opk.h"
#include "havok.h"
#include "syscalls.h"  /* SeraphSleep, SeraphCreateThread, SysNtUserGetAsyncKeyState */

#pragma optimize("", off)

extern int Overlay_GetFlyDirHotkey(void);

#define BODY_POS_X              0x1C0u
#define BODY_LINEAR_VEL         0x230u

#define CAM_AOB_LEN   8
#define CAM_OFF_YAW   0x18
#define CAM_OFF_PITCH 0x1C

static inline BOOL is_user_heap_ptr(UINT64 p) {
    return (p >= 0x10000ULL && p < 0x7FFFFFFFFFFFFULL && (p & 7) == 0);
}

static inline BOOL is_sane_world_pos(float x, float y, float z) {
    if (!(x == x && y == y && z == z)) return FALSE;
    if (fabsf(x) > 500000.0f || fabsf(y) > 500000.0f || fabsf(z) > 500000.0f) return FALSE;
    return TRUE;
}

static int    s_camHookId      = -1;
static UINT64 s_camCaveVA      = 0;
static float  s_lastYaw        = 0.0f;
static UINT64 s_cam_preScanVA  = 0;
static UINT64 s_cachedCamBase  = 0;
static DWORD  s_lastCamBaseRead = 0;

void Fly_SetCamPreScanResult(UINT64 va) { s_cam_preScanVA = va; }

#include "xor_strings.h"

static void install_cam_hook(UINT64 cr3, UINT64 d2Base) {
    s_camHookId = -1;
    s_cachedCamBase = 0; s_lastCamBaseRead = 0;
    if (!cr3 || !d2Base) return;
    
    UINT64 camAobVA = 0;
    if (s_cam_preScanVA >= d2Base) {
        camAobVA = s_cam_preScanVA;
    } else {
        camAobVA = d2Base + SecureReadStatic(&OBF_OFF_Fly_Cam);
    }

    UINT8 tgt[5] = {0};
    if (camAobVA >= d2Base) {
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, camAobVA, tgt, 5);
        BYOVD_UNLOCK();
    }

    static const UINT8 EXPECT[5] = {0xF3, 0x0F, 0x10, 0x47, 0x1C};
    if (memcmp(tgt, EXPECT, 5) != 0) {
        DEBUG_FLY("Fly: cam offset 0x%I64X mismatch [%02X %02X %02X %02X %02X] -- running fresh AOB scan",
                  camAobVA, tgt[0], tgt[1], tgt[2], tgt[3], tgt[4]);
        BYOVD_LOCK();
        UINT64 scannedVA = BYOVD_ScanPatternText(cr3, d2Base, k_cam_pat, k_cam_mask, 8);
        BYOVD_UNLOCK();
        if (scannedVA >= d2Base) {
            camAobVA = scannedVA;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, camAobVA, tgt, 5);
            BYOVD_UNLOCK();
            DEBUG_FLY("Fly: cam AOB found @ 0x%I64X [%02X %02X %02X %02X %02X]", 
                      camAobVA, tgt[0], tgt[1], tgt[2], tgt[3], tgt[4]);
        }
    }

    if (memcmp(tgt, EXPECT, 5) != 0) { 
        DEBUG_FLY("Fly: cam target mismatch aborted (camAobVA=0x%I64X)", camAobVA); 
        s_camCaveVA = 0; 
        return; 
    }

    if (!s_camCaveVA) {
        s_camCaveVA = CaveFinder_FindFirst(cr3, d2Base, 32);
    }
    if (!s_camCaveVA) { DEBUG_FLY("Fly: no cave for cam hook"); return; }

    UINT64 mailboxVA = s_camCaveVA, scBase = s_camCaveVA + 0x08;
    UINT8 sc[13];
    sc[0]=0x48; sc[1]=0xB8; *(UINT64*)(&sc[2])=mailboxVA; sc[10]=0x48; sc[11]=0x89; sc[12]=0x38;
    UINT64 zero = 0;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, mailboxVA, &zero, 8);
    BYOVD_UNLOCK();
    s_camHookId = LazyHook_Install(cr3, camAobVA, 5, sc, 13, scBase);
    if (s_camHookId >= 0) DEBUG_FLY("Fly: cam hook OK id=%d @ 0x%I64X (mailbox=0x%I64X)", s_camHookId, camAobVA, mailboxVA); else s_camCaveVA = 0;
}
static void remove_cam_hook(UINT64 cr3) {
    if (s_camHookId >= 0 && cr3) { LazyHook_Remove(s_camHookId, cr3); s_camHookId = -1; }
    s_cachedCamBase = 0;
    s_lastCamBaseRead = 0;
}



static BOOL read_cam_from_hook(UINT64 cr3, float* yaw, float* pitch) {
    if (s_camCaveVA && s_camHookId >= 0) {
        DWORD now = GetTickCount();
        UINT64 camBase = s_cachedCamBase;
        if (camBase == 0 || (now - s_lastCamBaseRead >= 100)) {
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, s_camCaveVA, &camBase, 8);
            BYOVD_UNLOCK();
            if (camBase) {
                s_cachedCamBase = camBase;
                s_lastCamBaseRead = now;
            }
        }
        if (camBase) {
            float angles[2] = {0.0f, 0.0f};
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, camBase + CAM_OFF_YAW, angles, 8);
            BYOVD_UNLOCK();
            if (angles[0] == angles[0] && fabsf(angles[0]) < 7.0f) { *yaw = angles[0]; s_lastYaw = *yaw; }
            if (angles[1] == angles[1] && fabsf(angles[1]) < 2.0f) { *pitch = angles[1]; }
            return TRUE;
        }
    }

    /* ── Passiva 100% via View Matrix (Sem hooks / Sem detours) ── */
    float viewMat[16], projMat[16];
    if (ESP_GetCachedMatrices(viewMat, projMat)) {
        /* In Destiny 2 View Matrix: Forward vector is Row 2 (-Z in view space) */
        float fwdX = viewMat[2];
        float fwdY = viewMat[6];
        float fwdZ = viewMat[10];
        if (fwdX != 0.0f || fwdY != 0.0f) {
            *yaw = atan2f(-fwdX, fwdY);
            *pitch = asinf(-fwdZ);
            s_lastYaw = *yaw;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL   s_enabled          = FALSE;
static BOOL   s_flyDirEnabled    = FALSE;
static DWORD  s_lastTick         = 0;
static LARGE_INTEGER s_lastQpc   = {0};



static float s_cosY = 1.0f, s_sinY = 0.0f, s_cosP = 1.0f, s_sinP = 0.0f;

static float  s_gravComp       = 0.2f;
static BOOL   s_bracketWasDown = FALSE;

static volatile LONG s_speedWASD_cache = 5;
static volatile LONG s_speedDir_cache  = 5;
static HANDLE        s_flyThread       = NULL;
static volatile LONG s_flyThreadStop   = 0;

static DWORD WINAPI Fly_ThreadProc(LPVOID lpParam);
void Fly_Tick_DoWork(int speedWASD, int speedDir);

void Fly_OnAttach(void)
{
    MUTATE_START
    s_enabled     = FALSE;
    s_flyDirEnabled = FALSE;
    s_lastTick       = 0;
    s_lastQpc.QuadPart = 0;

    s_camHookId = -1;
    s_camCaveVA = 0;
    s_lastYaw = 0.0f;
    s_gravComp = 0.2f;
    s_bracketWasDown = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    DEBUG_FLY("=== Fly_OnAttach: cr3=0x%I64X base=0x%I64X ===", cr3, d2Base);
    if (!cr3 || !d2Base) { DEBUG_FLY("Fly_OnAttach: ABORT -- cr3 or d2Base null"); goto _foa_end; }

    install_cam_hook(cr3, d2Base);
    ESP_AcquireUpdateThread();

    InterlockedExchange(&s_flyThreadStop, 0);
    if (!s_flyThread) {
        s_flyThread = SeraphCreateThread(Fly_ThreadProc, NULL);
        if (s_flyThread) {
            DEBUG_FLY("Fly_OnAttach: thread created h=0x%p", s_flyThread);
        } else {
            DEBUG_FLY("Fly_OnAttach: FATAL -- CreateThread FAILED err=%lu", GetLastError());
        }
    } else {
        DEBUG_FLY("Fly_OnAttach: thread already running h=0x%p", s_flyThread);
    }

_foa_end:
    MUTATE_END
}

void Fly_OnDetach(void)
{
    MUTATE_START
    InterlockedExchange(&s_flyThreadStop, 1);
    if (s_flyThread) {
        WaitForSingleObject(s_flyThread, 3000);
        SysNtClose(s_flyThread);
        s_flyThread = NULL;
    }
    s_enabled  = FALSE;
    s_flyDirEnabled = FALSE;
    UINT64 cr3 = GetDestiny2CR3();
    remove_cam_hook(cr3);
    DEBUG_FLY("Fly_OnDetach: state cleared");
    ESP_ReleaseUpdateThread();
    MUTATE_END
}

void Fly_ResetSoftState(void)
{
    s_cachedCamBase = 0;
    s_lastCamBaseRead = 0;

    LazyHook_ResetLocalState();
    CaveFinder_ClearReservations();
}

void Fly_ResetOnTransition(void)
{
}

void  Fly_SetEnabled(BOOL en)    { s_enabled = en; if (en) { s_lastTick = 0; s_gravComp = 0.2f; } }
BOOL  Fly_IsEnabled(void)        { return s_enabled; }
void  FlyDir_SetEnabled(BOOL en) { s_flyDirEnabled = en; if (en) s_lastTick = 0; }
BOOL  FlyDir_IsEnabled(void)     { return s_flyDirEnabled; }

UINT64 Fly_GetLpEp(void) {
    UINT64 directRb = LP_GetLocalPlayerRigidBody();
    if (directRb >= 0x100000ULL) return directRb;
    
    if (!g_HavokState.hkp_world_va) {
        Havok_Init();
    }

    static HavokEntity tmpEnts[HAVOK_MAX_RESULTS];
    int entCount = Havok_GetEntities(tmpEnts, HAVOK_MAX_RESULTS);
    UINT64 ep = Havok_GetLocalPlayerEp();

    static DWORD s_lastDiagMs = 0;
    DWORD now = GetTickCount();
    if (now - s_lastDiagMs >= 2000) {
        s_lastDiagMs = now;
        DEBUG_FLY("[FLY_DIAG] directRb=0x%I64X havokEp=0x%I64X (hkpWorld=0x%I64X, entCount=%d, camValid=%d)",
                  directRb, ep, g_HavokState.hkp_world_va, entCount, g_camWorldPosValid);
    }

    return ep;
}


BOOL Fly_RestoreCamHookOnDemand(UINT64 cr3, UINT64 d2Base) {
    /* Dummy fallback to keep aimbot.c link happy */
    return FALSE;
}

UINT64 Fly_GetPObjDecryptedVA(void) { return 0; }

UINT64 Fly_GetCamBase(void) {
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !s_camCaveVA || s_camHookId < 0) return 0;
    
    DWORD now = GetTickCount();
    UINT64 camBase = s_cachedCamBase;
    if (camBase == 0 || (now - s_lastCamBaseRead >= 100)) {
        BYOVD_LOCK();
        BYOVD_ReadVA_NoCache(cr3, s_camCaveVA, &camBase, 8);
        BYOVD_UNLOCK();
        if (camBase) {
            s_cachedCamBase = camBase;
            s_lastCamBaseRead = now;
        }
    }
    return camBase;
}

void Fly_GetCamTrig(float* cY, float* sY, float* cP, float* sP) {
    if (cY) *cY = s_cosY; if (sY) *sY = s_sinY;
    if (cP) *cP = s_cosP; if (sP) *sP = s_sinP;
}

BOOL Fly_ReadCam(float* yaw, float* pitch, UINT64* camBaseOut) {
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;
    UINT64 camBase = Fly_GetCamBase();
    if (camBaseOut) *camBaseOut = camBase;
    float y = s_lastYaw, p = 0.0f;
    BOOL ok = read_cam_from_hook(cr3, &y, &p);
    if (yaw) *yaw = y; if (pitch) *pitch = p; return ok;
}

BOOL Fly_WriteCam(float yaw, float pitch) {
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !s_camCaveVA || s_camHookId < 0) return FALSE;
    UINT64 camBase = Fly_GetCamBase();
    if (!camBase) return FALSE;
    float angles[2] = { yaw, pitch };
    BYOVD_LOCK();
    BOOL ok = BYOVD_WriteVA(cr3, camBase + CAM_OFF_YAW, angles, 8);
    BYOVD_UNLOCK();
    return ok;
}

UINT64 Fly_GetCaveVA(void) {
    return s_camCaveVA;
}
void Fly_SetLpEpPreScanResult(UINT64 va)  { (void)va; }

BOOL Fly_GetCamWorldPos(float* x, float* y, float* z) {
    if (!g_camWorldPosValid || !x || !y || !z) return FALSE;
    *x = g_camWorldPos.x;
    *y = g_camWorldPos.y;
    *z = g_camWorldPos.z;
    return TRUE;
}

static DWORD WINAPI Fly_ThreadProc(LPVOID lpParam) {
    (void)lpParam;
#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
    HANDLE hFlyTimer = CreateWaitableTimerExW(NULL, NULL,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (!hFlyTimer) {
        DEBUG_FLY("Fly_ThreadProc: FAILED to create timer");
        return 0;
    }
    DEBUG_FLY("Fly_ThreadProc: STARTED tid=%lu", GetCurrentThreadId());
    while (!s_flyThreadStop) {
        if (s_enabled || s_flyDirEnabled || OPK_IsEnabled()) {
            Fly_Tick_DoWork(InterlockedExchangeAdd(&s_speedWASD_cache, 0),
                            InterlockedExchangeAdd(&s_speedDir_cache,  0));
        }
        LARGE_INTEGER li; li.QuadPart = -55555LL; /* 5.56ms (180Hz update rate) */
        SetWaitableTimer(hFlyTimer, &li, 0, NULL, NULL, FALSE);
        WaitForSingleObject(hFlyTimer, INFINITE);
    }
    SysNtClose(hFlyTimer);
    DEBUG_FLY("Fly_ThreadProc: EXITING");
    return 0;
}

void Fly_Tick(int speedWASD, int speedDir)
{
    InterlockedExchange(&s_speedWASD_cache, speedWASD);
    InterlockedExchange(&s_speedDir_cache,  speedDir);
}

void Fly_Tick_DoWork(int speedWASD, int speedDir)
{
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    BYOVD_FlushPhysCache();

    UINT64 lpBody = Fly_GetLpEp();
    if (lpBody < 0x10000ULL) {
        g_camWorldPosValid = FALSE;
        return;
    }

    float pos[3] = {0.0f, 0.0f, 0.0f};
    BYOVD_LOCK();
    BOOL rdPosOk = BYOVD_ReadVA_NoCache(cr3, lpBody + BODY_POS_X, pos, 12);
    BYOVD_UNLOCK();

    /* Invalidate RigidBody reference strictly on unreadable memory or all-zero position */
    if (!rdPosOk || (pos[0] == 0.0f && pos[1] == 0.0f && pos[2] == 0.0f) || !is_sane_world_pos(pos[0], pos[1], pos[2])) {
        g_camWorldPosValid = FALSE;
        Havok_Reset();
        return;
    }

    g_camWorldPos.x = pos[0];
    g_camWorldPos.y = pos[1];
    g_camWorldPos.z = pos[2];
    g_camWorldPosValid = TRUE;

    static LARGE_INTEGER s_freq = {0};
    if (s_freq.QuadPart == 0) {
        QueryPerformanceFrequency(&s_freq);
    }
    LARGE_INTEGER nowQpc;
    QueryPerformanceCounter(&nowQpc);

    float dt = 0.00556f;
    if (s_lastQpc.QuadPart > 0) {
        dt = (float)(nowQpc.QuadPart - s_lastQpc.QuadPart) / (float)s_freq.QuadPart;
        if (dt <= 0.0f || dt > 0.1f) dt = 0.00556f;
    }
    s_lastQpc = nowQpc;

    float yaw = s_lastYaw, pitch = 0.0f;
    read_cam_from_hook(cr3, &yaw, &pitch);
    if (pitch < -1.492256522f) pitch = -1.492256522f;
    if (pitch >  1.492256522f) pitch =  1.492256522f;
    s_cosY = cosf(yaw); s_sinY = sinf(yaw);
    s_cosP = cosf(pitch); s_sinP = sinf(pitch);

    { BOOL bClose = (SysNtUserGetAsyncKeyState(0xDB) & 0x8000) != 0;
      BOOL bOpen  = (SysNtUserGetAsyncKeyState(0xDD) & 0x8000) != 0;
      if (!s_bracketWasDown && bOpen)  s_gravComp += 0.1f;
      if (!s_bracketWasDown && bClose) s_gravComp -= 0.1f;
      if (s_gravComp < -2.0f) s_gravComp = -2.0f;
      if (s_gravComp >  2.0f) s_gravComp =  2.0f;
      s_bracketWasDown = bClose || bOpen; }

    if (!(s_cosY == s_cosY && s_sinY == s_sinY)) {
        return;
    }



    if (!s_enabled && !s_flyDirEnabled) return;

    int fdKey = Overlay_GetFlyDirHotkey();
    if (fdKey == 0) fdKey = VK_XBUTTON2;
    BOOL isDirPressed = FALSE;
    if (fdKey >= VK_PAD_L2 && fdKey <= VK_PAD_RIGHT) {
        isDirPressed = ControllerInput_IsKeyPressed(fdKey);
    } else {
        isDirPressed = (SysNtUserGetAsyncKeyState(fdKey) & 0x8000) ? TRUE : FALSE;
    }

    if (!s_enabled && !isDirPressed) return;

    BOOL didDirWrite = FALSE;
    if (s_flyDirEnabled && isDirPressed) {
        float step = (float)(speedDir + 2) * 16.0f * dt;
        float pos[3] = {0};
        BYOVD_LOCK();
        BOOL rOk = BYOVD_ReadVA_NoCache(cr3, lpBody + BODY_POS_X, pos, 12);
        BYOVD_UNLOCK();
        if (rOk && (pos[0] != 0.0f || pos[1] != 0.0f || pos[2] != 0.0f)) {
            pos[0] += s_cosY * s_cosP * step;
            pos[1] += s_sinY * s_cosP * step;
            pos[2] -= s_sinP * step;

            BYOVD_LOCK();
            BYOVD_WriteVA_Fresh(cr3, lpBody + BODY_POS_X, pos, 12);
            BYOVD_UNLOCK();
            didDirWrite = TRUE;

            static DWORD s_lastDirLog = 0;
            DWORD now = GetTickCount();
            if (now - s_lastDirLog >= 500) {
                s_lastDirLog = now;
                DEBUG_FLY("Fly_Tick_DoWork: Directional write on body 0x%I64X -> New Pos: %.3f, %.3f, %.3f",
                          lpBody, pos[0], pos[1], pos[2]);
            }
        }
    }

    if (s_enabled) {
        float vx = 0.0f, vy = 0.0f, vz = 0.0f;
        float spd = (float)(speedWASD + 2) * 10.0f;
        float cosY = s_cosY, sinY = s_sinY;
        float cosP = s_cosP, sinP = s_sinP;

        if (SysNtUserGetAsyncKeyState('W') & 0x8000)     { vx += cosY*cosP*spd; vz += sinY*cosP*spd; vy -= sinP*spd; }
        if (SysNtUserGetAsyncKeyState('S') & 0x8000)     { vx -= cosY*cosP*spd; vz -= sinY*cosP*spd; vy += sinP*spd; }
        if (SysNtUserGetAsyncKeyState('A') & 0x8000)     { vx -= sinY*spd;      vz += cosY*spd; }
        if (SysNtUserGetAsyncKeyState('D') & 0x8000)     { vx += sinY*spd;      vz -= cosY*spd; }
        if (SysNtUserGetAsyncKeyState(VK_SPACE) & 0x8000)  vy += spd;
        if (SysNtUserGetAsyncKeyState(VK_SHIFT) & 0x8000) vy -= spd;
        vy += s_gravComp;

        float write_buf[8];
        write_buf[0] = vx;
        write_buf[1] = vz;
        write_buf[2] = vy;
        write_buf[3] = 0.0f;
        write_buf[4] = 0.0f;
        write_buf[5] = 0.0f;
        write_buf[6] = 0.0f;
        write_buf[7] = 0.0f;

        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, lpBody + BODY_LINEAR_VEL, write_buf, 32);
        BYOVD_UNLOCK();

        static DWORD s_lastWasdLog = 0;
        DWORD now = GetTickCount();
        if (now - s_lastWasdLog >= 500) {
            s_lastWasdLog = now;
            DEBUG_FLY("Fly_Tick_DoWork: WASD write on body 0x%I64X -> Velocity: %.3f, %.3f, %.3f",
                      lpBody, vx, vz, vy);
        }
    }
    else if (didDirWrite) {
        static const float zero3[3] = {0.0f, 0.0f, 0.0f};
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, lpBody + BODY_LINEAR_VEL, zero3, 12);
        BYOVD_UNLOCK();
        DEBUG_FLY("Fly_Tick_DoWork: Zeroed velocity on body 0x%I64X to prevent drift", lpBody);
    }
}
