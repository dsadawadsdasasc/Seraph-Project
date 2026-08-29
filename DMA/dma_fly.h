/*
 * dma_fly.h  --  DMA scatter-optimized fly (follows fly.txt design).
 *
 * This is the DMA-specific fly implementation.  The external/Loader build
 * continues to use fly.c / fly.h unchanged.
 *
 * Key differences from fly.c:
 *   - Scatter-read batching via DMA_Tick_Begin/AddRead/Execute for Havok scans
 *   - enumerate_rigid_bodies() + find_local_rigid_body() from fly.txt
 *   - entity_data validation (CHARACTER_MOTION_VT / KEYFRAMED_MOTION_VT)
 *   - No LP entity hook, no cam dump diagnostics, no SilentAim spy poll
 *   - Camera hook (lazyhook) KEPT — reads yaw/pitch via mailbox
 *   - Gravity compensation KEPT
 *   - WASD fly uses velocity writes (same as fly.c)
 *   - FlyDir uses position writes (same as fly.c)
 *
 * Extra checks from fly.c that are COMMENTED OUT (available for reference):
 *   - Vtable death-check
 *   - Post-death TL staleness guard
 *   - WATCHDOG hard reinit
 *   - HookSeeder
 *   - TL identity guard
 *   - hkpWorld fast-path peek / self-heal
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Lifecycle ──────────────────────────────────────────────────────────── */
void DMA_Fly_OnAttach(void);
void DMA_Fly_OnDetach(void);
void DMA_Fly_ResetSoftState(void);

/* ── Per-frame tick ─────────────────────────────────────────────────────── */
void DMA_Fly_Tick(int speedWASD, int speedDir);

/* ── Toggle ─────────────────────────────────────────────────────────────── */
void  DMA_Fly_SetEnabled(BOOL en);
BOOL  DMA_Fly_IsEnabled(void);
void  DMA_FlyDir_SetEnabled(BOOL en);
BOOL  DMA_FlyDir_IsEnabled(void);

/* ── Accessors ──────────────────────────────────────────────────────────── */
UINT64 DMA_Fly_GetLpEp(void);
void   DMA_Fly_GetCamTrig(float* cY, float* sY, float* cP, float* sP);
BOOL   DMA_Fly_ReadCam(float* yaw, float* pitch, UINT64* camBaseOut);
BOOL   DMA_Fly_WriteCam(float yaw, float pitch);
UINT64 DMA_Fly_GetCamBase(void);

/* ── Pre-scan handoff (from FeatureInitThread mega-scan) ────────────────── */
void DMA_Fly_SetCamPreScanResult(UINT64 va);

#ifdef __cplusplus
}
#endif