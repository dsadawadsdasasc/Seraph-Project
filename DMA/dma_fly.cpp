/*
 * dma_fly.cpp -- DMA Fly implementation (Identical to Loader/fly.c for 1:1 parity)
 */
#include "ThemidaSDK.h"
#include "fly.h"
#include "dma_fly.h"
#include "lists.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "aimbot.h"
#include "attach.h"
#include "debug.h"
#include "cave_finder.h"
#include "lazyhook.h"
#include "esp.h"
#include "local_player.h"
#include "guardian.h"
#include "tigerlist.h"
#include <windows.h>
#include "aob_patterns.h"
#include <math.h>
#include <float.h>
#include <string.h>
#include "controller_input.h"
#include "opk.h"
#include "havok.h"
#include "syscalls.h"

#pragma optimize("", off)

extern "C" int Overlay_GetFlyDirHotkey(void);

static UINT64 s_cachedFlyBody    = 0;
static BOOL   s_flyInitialized   = FALSE;
static UINT64 s_hkpPreScanVA     = 0;

#define BODY_VTABLE             0x000u
#define BODY_USER_DATA          0x014u
#define BODY_WORLD_PTR          0x018u
#define BODY_ENTITY_DATA        0x150u
#define BODY_MOTION_TYPE        0x168u
#define BODY_POS_X              0x1C0u
#define BODY_LINEAR_VEL         0x230u
#define BODY_ANGULAR_VEL        0x240u

#define WORLD_ACTIVE_ISLANDS    0x40u
#define WORLD_ACTIVE_COUNT      0x48u
#define WORLD_INACTIVE_ISLANDS  0x50u
#define WORLD_INACTIVE_COUNT    0x58u
#define ISLAND_ENTITY_ARRAY     0x68u
#define ISLAND_ENTITY_COUNT     0x70u

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

extern "C" HavokVec3 g_camWorldPos;
extern "C" BOOL      g_camWorldPosValid;

typedef struct { UINT64 ent_array; int32_t ent_count; } IslandData;

#define MAX_ISLANDS 128
#define MAX_PTRS    512

static int collect_island_ptrs(UINT64 world, UINT64* island_ptrs, int max_islands, UINT64 cr3)
{
    static const UINT32 list_offsets[] = { 0x40, 0x50 };
    const int list_offsets_n = (int)(sizeof(list_offsets) / sizeof(list_offsets[0]));

    UINT64 seen_lists[16];
    memset(seen_lists, 0, sizeof(seen_lists));
    int seen_n = 0;
    int total_collected = 0;

    for (int li = 0; li < list_offsets_n && total_collected < max_islands; li++) {
        UINT64 list_arr = 0;
        int32_t list_cnt = 0;

        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, world + list_offsets[li],     &list_arr, 8);
        BYOVD_ReadVA(cr3, world + list_offsets[li] + 8, &list_cnt, 4);
        BYOVD_UNLOCK();

        if (list_cnt <= 0 || list_cnt > 2000 || !is_user_heap_ptr(list_arr)) continue;

        BOOL dup = FALSE;
        for (int i = 0; i < seen_n; i++) {
            if (seen_lists[i] == list_arr) { dup = TRUE; break; }
        }
        if (dup) continue;
        if (seen_n < 16) seen_lists[seen_n++] = list_arr;

        int to_read = list_cnt;
        if (total_collected + to_read > max_islands) {
            to_read = max_islands - total_collected;
        }

        if (to_read > 0) {
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, list_arr, &island_ptrs[total_collected], to_read * 8);
            BYOVD_UNLOCK();
            total_collected += to_read;
        }
    }

    return total_collected;
}

static int collect_body_ptrs(const UINT64* island_ptrs, int n_islands,
                              UINT64* body_ptrs, int max_ptrs, UINT64 cr3)
{
    if (n_islands > MAX_ISLANDS) n_islands = MAX_ISLANDS;
    IslandData island_data[MAX_ISLANDS];
    memset(island_data, 0, sizeof(island_data));

    BYOVD_LOCK();
    for (int i = 0; i < n_islands; i++) {
        if (!is_user_heap_ptr(island_ptrs[i])) continue;
        BYOVD_ReadVA(cr3, island_ptrs[i] + ISLAND_ENTITY_ARRAY, &island_data[i].ent_array, 8);
        BYOVD_ReadVA(cr3, island_ptrs[i] + ISLAND_ENTITY_COUNT, &island_data[i].ent_count, 4);
    }
    BYOVD_UNLOCK();

    int n_ptrs = 0;
    for (int i = 0; i < n_islands && n_ptrs < max_ptrs; i++) {
        IslandData* id = &island_data[i];
        if (!is_user_heap_ptr(id->ent_array)) continue;
        if (id->ent_count <= 0 || id->ent_count > 256) continue;
        int n = id->ent_count;
        if (n_ptrs + n > max_ptrs) n = max_ptrs - n_ptrs;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, id->ent_array, &body_ptrs[n_ptrs], n * 8);
        BYOVD_UNLOCK();
        n_ptrs += n;
    }
    return n_ptrs;
}

static void read_body_identity(UINT64 body_ptr, UINT64* ent_data_out, UINT64* world_ptr_out, UINT64 cr3)
{
    if (ent_data_out) *ent_data_out = 0;
    if (world_ptr_out) *world_ptr_out = 0;
    if (!is_user_heap_ptr(body_ptr)) return;

    UINT64 ed = 0, wp = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, body_ptr + BODY_ENTITY_DATA, &ed, 8);
    BYOVD_ReadVA(cr3, body_ptr + BODY_WORLD_PTR,   &wp, 8);
    BYOVD_UNLOCK();

    if (ent_data_out)  *ent_data_out  = ed;
    if (world_ptr_out) *world_ptr_out = wp;
}

static UINT64 find_local_rigid_body(const float lpPos[3], UINT64 d2Base, UINT64 cr3)
{
    UINT64 hkWorld_VA = 0;
    if (Havok_Init()) {
        hkWorld_VA = s_hkpPreScanVA;
    }
    if (!hkWorld_VA) {
        BYOVD_LOCK();
        hkWorld_VA = BYOVD_ScanPatternText(cr3, d2Base, k_hkp_pat, k_hkp_mask, 9);
        BYOVD_UNLOCK();
    }
    if (!hkWorld_VA) hkWorld_VA = d2Base + SecureReadStatic(&OBF_OFF_Havok);
    if (!hkWorld_VA) return 0;

    UINT64 world = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, hkWorld_VA, &world, 8);
    BYOVD_UNLOCK();
    if (!is_user_heap_ptr(world)) return 0;

    UINT64 island_ptrs[MAX_ISLANDS];
    int n_islands = collect_island_ptrs(world, island_ptrs, MAX_ISLANDS, cr3);
    if (n_islands <= 0) return 0;

    UINT64 body_ptrs[MAX_PTRS];
    int n_ptrs = collect_body_ptrs(island_ptrs, n_islands, body_ptrs, MAX_PTRS, cr3);
    if (n_ptrs <= 0) return 0;

    UINT64 char_motion_vt = (g_character_motion_vtable_rva != 0) ? (d2Base + g_character_motion_vtable_rva) : 0;
    UINT64 sparrow_vt     = (g_sparrow_motion_vtable_rva != 0)   ? (d2Base + g_sparrow_motion_vtable_rva)   : (char_motion_vt ? (char_motion_vt + 0x330ULL) : 0);

    if (!char_motion_vt && !sparrow_vt) return 0;

    UINT64 closest_body = 0;
    float  min_dist_sq  = 9.0f; /* 3.0m max threshold */

    for (int i = 0; i < n_ptrs; i++) {
        UINT64 b = body_ptrs[i];
        if (!is_user_heap_ptr(b)) continue;

        UINT64 ent_data = 0, world_ptr = 0;
        read_body_identity(b, &ent_data, &world_ptr, cr3);

        if (!is_user_heap_ptr(world_ptr)) continue;
        
        BOOL vt_match = (char_motion_vt != 0 && ent_data == char_motion_vt) ||
                        (sparrow_vt != 0 && ent_data == sparrow_vt);
        if (!vt_match) continue;

        float pos[3] = {0};
        BYOVD_LOCK();
        BOOL rdOk = BYOVD_ReadVA(cr3, b + BODY_POS_X, pos, 12);
        BYOVD_UNLOCK();

        if (!rdOk || !is_sane_world_pos(pos[0], pos[1], pos[2])) continue;

        float dx = pos[0] - lpPos[0];
        float dy = pos[1] - lpPos[1];
        float dz = pos[2] - lpPos[2];
        float dist_sq = dx*dx + dy*dy + dz*dz;

        if (dist_sq < min_dist_sq) {
            min_dist_sq  = dist_sq;
            closest_body = b;
        }
    }

    return closest_body;
}

static int    s_camHookId       = -1;
static UINT64 s_camCaveVA       = 0;
static float  s_lastYaw         = 0.0f;
static UINT64 s_cam_preScanVA   = 0;
static UINT64 s_cachedCamBase   = 0;
static DWORD  s_lastCamBaseRead = 0;

extern "C" {

void Fly_SetCamPreScanResult(UINT64 va) { s_cam_preScanVA = va; }
void Fly_SetHkpPreScanResult(UINT64 va) { s_hkpPreScanVA = va; }
void Fly_SetLpEpPreScanResult(UINT64 va) { (void)va; }
void Fly_SetPObjPreScanResult(UINT64 va) { (void)va; }

void DMA_Fly_SetCamPreScanResult(UINT64 va) { s_cam_preScanVA = va; }

}

#include "xor_strings.h"

static void install_cam_hook(UINT64 cr3, UINT64 d2Base) {
    s_camHookId = -1;
    s_cachedCamBase = 0; s_lastCamBaseRead = 0;
    if (!cr3 || !d2Base) return;
    
    UINT64 camAobVA = s_cam_preScanVA;
    if (!camAobVA) {
        BYOVD_LOCK();
        camAobVA = BYOVD_ScanPatternText(cr3, d2Base, k_cam_pat, k_cam_mask, 8);
        BYOVD_UNLOCK();
    }
    if (!camAobVA) { DEBUG_FLY("Fly: cam AOB not found"); return; }

    if (!s_camCaveVA) {
        s_camCaveVA = CaveFinder_FindFirst(cr3, d2Base, 32);
    }
    if (!s_camCaveVA) { DEBUG_FLY("Fly: no cave for cam hook"); return; }
    UINT8 tgt[5] = {0};
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, camAobVA, tgt, 5);
    BYOVD_UNLOCK();
    static const UINT8 EXPECT[5] = {0xF3, 0x0F, 0x10, 0x47, 0x1C};
    if (memcmp(tgt, EXPECT, 5) != 0) { DEBUG_FLY("Fly: cam target mismatch"); s_camCaveVA = 0; return; }
    UINT64 mailboxVA = s_camCaveVA, scBase = s_camCaveVA + 0x08;
    UINT8 sc[13];
    sc[0]=0x48; sc[1]=0xB8; *(UINT64*)(&sc[2])=mailboxVA; sc[10]=0x48; sc[11]=0x89; sc[12]=0x38;
    UINT64 zero = 0;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, mailboxVA, &zero, 8);
    BYOVD_UNLOCK();
    s_camHookId = LazyHook_Install(cr3, camAobVA, 5, sc, 13, scBase);
    if (s_camHookId >= 0) DEBUG_FLY("Fly: cam hook OK id=%d", s_camHookId); else s_camCaveVA = 0;
}

static void remove_cam_hook(UINT64 cr3) {
    if (s_camHookId >= 0 && cr3) { LazyHook_Remove(s_camHookId, cr3); s_camHookId = -1; }
    s_cachedCamBase = 0;
    s_lastCamBaseRead = 0;
}

static BOOL read_cam_from_hook(UINT64 cr3, float* yaw, float* pitch) {
    if (!s_camCaveVA || s_camHookId < 0) return FALSE;
    
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
    if (!camBase) return FALSE;
    float angles[2] = {0.0f, 0.0f};
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, camBase + CAM_OFF_YAW, angles, 8);
    BYOVD_UNLOCK();
    if (angles[0] == angles[0] && fabsf(angles[0]) < 7.0f) { *yaw = angles[0]; s_lastYaw = *yaw; }
    if (angles[1] == angles[1] && fabsf(angles[1]) < 2.0f) { *pitch = angles[1]; }
    return TRUE;
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

extern "C" {

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
    s_cachedFlyBody = 0;
    s_flyInitialized = FALSE;

    /* cam hook and fly thread deferred to first Fly_SetEnabled(TRUE) call */
    DEBUG_FLY("Fly_OnAttach: deferred init — cam hook and thread will start on first enable");
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
    s_cachedFlyBody = 0;
    s_flyInitialized = FALSE;
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
    s_cachedFlyBody = 0;
    s_flyInitialized = FALSE;

    LazyHook_ResetLocalState();
    CaveFinder_ClearReservations();
}

void Fly_ResetOnTransition(void)
{
    s_cachedFlyBody = 0;
    s_flyInitialized = FALSE;
}

void  Fly_SetEnabled(BOOL en)    {
    if (en && !s_flyThread) {
        /* Lazy init: install cam hook and start thread on first enable */
        UINT64 cr3    = GetDestiny2CR3();
        UINT64 d2Base = GetDestiny2Base();
        if (cr3 && d2Base) {
            install_cam_hook(cr3, d2Base);
            InterlockedExchange(&s_flyThreadStop, 0);
            s_flyThread = SeraphCreateThread(Fly_ThreadProc, NULL);
        }
    }
    s_enabled = en;
    if (en) { s_lastTick = 0; s_gravComp = 0.2f; }
}
BOOL  Fly_IsEnabled(void)        { return s_enabled; }
void  FlyDir_SetEnabled(BOOL en) { s_flyDirEnabled = en; if (en) s_lastTick = 0; }
BOOL  FlyDir_IsEnabled(void)     { return s_flyDirEnabled; }

UINT64 Fly_GetLpEp(void) {
    if (s_cachedFlyBody && is_user_heap_ptr(s_cachedFlyBody)) {
        return s_cachedFlyBody;
    }
    return TigerList_GetLPHavokRigidBody();
}

BOOL Fly_RestoreCamHookOnDemand(UINT64 cr3, UINT64 d2Base) {
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

BOOL Fly_GetCamWorldPos(float* x, float* y, float* z) {
    if (!g_camWorldPosValid || !x || !y || !z) return FALSE;
    *x = g_camWorldPos.x;
    *y = g_camWorldPos.y;
    *z = g_camWorldPos.z;
    return TRUE;
}

void Fly_Tick(int speedWASD, int speedDir)
{
    InterlockedExchange(&s_speedWASD_cache, speedWASD);
    InterlockedExchange(&s_speedDir_cache,  speedDir);
}

/* ── DMA_Fly_* aliases ─────────────────────────────────────────────────── */
void  DMA_Fly_OnAttach(void)                     { Fly_OnAttach(); }
void  DMA_Fly_OnDetach(void)                     { Fly_OnDetach(); }
void  DMA_Fly_ResetSoftState(void)               { Fly_ResetSoftState(); }
void  DMA_Fly_Tick(int speedWASD, int speedDir)   { Fly_Tick(speedWASD, speedDir); }
void  DMA_Fly_SetEnabled(BOOL en)                { Fly_SetEnabled(en); }
BOOL  DMA_Fly_IsEnabled(void)                    { return Fly_IsEnabled(); }
void  DMA_FlyDir_SetEnabled(BOOL en)             { FlyDir_SetEnabled(en); }
BOOL  DMA_FlyDir_IsEnabled(void)                 { return FlyDir_IsEnabled(); }
UINT64 DMA_Fly_GetLpEp(void)                     { return Fly_GetLpEp(); }
void  DMA_Fly_GetCamTrig(float* cY, float* sY, float* cP, float* sP) { Fly_GetCamTrig(cY, sY, cP, sP); }
BOOL  DMA_Fly_ReadCam(float* yaw, float* pitch, UINT64* camBaseOut)   { return Fly_ReadCam(yaw, pitch, camBaseOut); }
BOOL  DMA_Fly_WriteCam(float yaw, float pitch)   { return Fly_WriteCam(yaw, pitch); }
UINT64 DMA_Fly_GetCamBase(void)                  { return Fly_GetCamBase(); }

} // extern "C"

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

void Fly_Tick_DoWork(int speedWASD, int speedDir)
{
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    BYOVD_FlushPhysCache();

    float s_lastLpPos[3] = {0};
    BOOL s_lastLpValid = LP_IsLocalPlayerValid() &&
                         TigerList_ReadLPPosition(s_lastLpPos) &&
                         is_sane_world_pos(s_lastLpPos[0], s_lastLpPos[1], s_lastLpPos[2]);

    if (!s_lastLpValid) {
        if (s_cachedFlyBody != 0) {
            DEBUG_FLY("Fly: LP invalid (menu/dead/zero coords) -> standby mode");
            s_cachedFlyBody = 0;
            s_flyInitialized = FALSE;
        }
        return;
    }

    /* Step 1: Validate existing s_cachedFlyBody if already cached */
    if (s_cachedFlyBody && s_flyInitialized) {
        float pos[3] = {0};
        BYOVD_LOCK();
        BOOL rdPosOk = BYOVD_ReadVA(cr3, s_cachedFlyBody + BODY_POS_X, pos, 12);
        BYOVD_UNLOCK();

        UINT64 ent_data = 0, world_ptr = 0;
        read_body_identity(s_cachedFlyBody, &ent_data, &world_ptr, cr3);

        UINT64 char_motion_vt = (g_character_motion_vtable_rva != 0) ? (d2Base + g_character_motion_vtable_rva) : 0;
        UINT64 sparrow_vt     = (g_sparrow_motion_vtable_rva != 0)   ? (d2Base + g_sparrow_motion_vtable_rva)   : (char_motion_vt ? (char_motion_vt + 0x330ULL) : 0);
        BOOL vt_ok = (char_motion_vt != 0 && ent_data == char_motion_vt) ||
                     (sparrow_vt != 0 && ent_data == sparrow_vt);

        BOOL dist_ok = TRUE;
        if (s_lastLpValid && rdPosOk) {
            float dx = pos[0] - s_lastLpPos[0];
            float dy = pos[1] - s_lastLpPos[1];
            float dz = pos[2] - s_lastLpPos[2];
            float distSq = dx*dx + dy*dy + dz*dz;
            dist_ok = (distSq <= 9.0f); /* Strict 3.0m deviation threshold */
        }

        BOOL bodyValid = (rdPosOk && is_sane_world_pos(pos[0], pos[1], pos[2]) &&
                          is_user_heap_ptr(world_ptr) && vt_ok && dist_ok);

        if (!bodyValid) {
            DEBUG_FLY("Fly: Invalidated stale body=0x%I64X (vt_ok=%d dist_ok=%d)", s_cachedFlyBody, vt_ok, dist_ok);
            s_cachedFlyBody = 0;
            s_flyInitialized = FALSE;
        }
    }

    /* Step 2: Instantly re-acquire rigid body if cache is 0 */
    if (s_cachedFlyBody == 0 && s_lastLpValid) {
        UINT64 closest = find_local_rigid_body(s_lastLpPos, d2Base, cr3);
        if (closest != 0) {
            UINT64 ent_data = 0, world_ptr = 0;
            read_body_identity(closest, &ent_data, &world_ptr, cr3);
            if (is_user_heap_ptr(ent_data) && is_user_heap_ptr(world_ptr)) {
                s_cachedFlyBody = closest;
                s_flyInitialized = TRUE;
                DEBUG_FLY("Fly: Re-acquired closest body=0x%I64X", s_cachedFlyBody);
            }
        }
    }

    float cam_pos[3] = {0.0f, 0.0f, 0.0f};
    BOOL cam_valid = FALSE;

    if (s_cachedFlyBody && s_flyInitialized) {
        float pos[3] = {0};
        BYOVD_LOCK();
        BOOL rdPosOk = BYOVD_ReadVA(cr3, s_cachedFlyBody + BODY_POS_X, pos, 12);
        BYOVD_UNLOCK();
        if (rdPosOk && is_sane_world_pos(pos[0], pos[1], pos[2])) {
            cam_pos[0] = pos[0]; cam_pos[1] = pos[1]; cam_pos[2] = pos[2];
            cam_valid = TRUE;
            Havok_SetCamPos(pos[0], pos[1], pos[2]);
        }
    }

    if (!cam_valid && s_lastLpValid) {
        cam_pos[0] = s_lastLpPos[0]; cam_pos[1] = s_lastLpPos[1]; cam_pos[2] = s_lastLpPos[2];
        cam_valid = TRUE;
    }

    if (cam_valid) {
        g_camWorldPos.x = cam_pos[0];
        g_camWorldPos.y = cam_pos[1];
        g_camWorldPos.z = cam_pos[2];
        g_camWorldPosValid = TRUE;
    } else {
        g_camWorldPosValid = FALSE;
    }

    static LARGE_INTEGER s_freq = {0};
    if (s_freq.QuadPart == 0) QueryPerformanceFrequency(&s_freq);
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

    if (s_cachedFlyBody == 0 || !is_user_heap_ptr(s_cachedFlyBody)) {
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
        BOOL rOk = BYOVD_ReadVA(cr3, s_cachedFlyBody + BODY_POS_X, pos, 12);
        BYOVD_UNLOCK();
        if (rOk && (pos[0] != 0.0f || pos[1] != 0.0f || pos[2] != 0.0f)) {
            pos[0] += s_cosY * s_cosP * step;
            pos[1] += s_sinY * s_cosP * step;
            pos[2] -= s_sinP * step;

            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_cachedFlyBody + BODY_POS_X, pos, 12);
            BYOVD_UNLOCK();
            didDirWrite = TRUE;
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
        BYOVD_WriteVA(cr3, s_cachedFlyBody + BODY_LINEAR_VEL, write_buf, 32);
        BYOVD_UNLOCK();
    }
    else if (didDirWrite) {
        static const float zero3[3] = {0.0f, 0.0f, 0.0f};
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_cachedFlyBody + BODY_LINEAR_VEL, zero3, 12);
        BYOVD_UNLOCK();
        DEBUG_FLY("Fly_Tick_DoWork: Zeroed velocity on body 0x%I64X to prevent drift", s_cachedFlyBody);
    }
}
