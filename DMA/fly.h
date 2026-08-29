/*
 * fly.h  --  DMA build: redirect to dma_fly.h
 *
 * Shadows Loader/fly.h so all callers (gui_core.cpp, etc.) compile unchanged
 * on the DMA build.  The /I"DMA" include path comes before /I"Loader".
 *
 * NOTE: gui_core.cpp is in Loader/ so it finds Loader/fly.h first.
 * To fix, Loader/fly.h has #ifdef SERAPH_DMA_BUILD guards redirecting here.
 * This file provides the actual declarations.
 */
#pragma once
#include "dma_fly.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Declare k_cam_pat/k_cam_mask as extern (defined in dma_fly.cpp) */
extern const UINT8 k_cam_pat[];
extern const UINT8 k_cam_mask[];

/* g_camWorldPos + g_camWorldPosValid (were in fly.c, now in dma_fly.cpp) */
#ifndef HAVOK_VEC3_DEFINED
#define HAVOK_VEC3_DEFINED
typedef struct { float x, y, z; } HavokVec3;
#endif
extern HavokVec3 g_camWorldPos;
extern BOOL      g_camWorldPosValid;

/* These are the actual C-linkage wrappers that gui_core.cpp calls.
 * They are defined in dma_fly.cpp with the standard Fly_* names. */
void   Fly_OnAttach(void);
void   Fly_OnDetach(void);
void   Fly_ResetSoftState(void);
void   Fly_Tick(int speedWASD, int speedDir);
void   Fly_SetEnabled(BOOL en);
BOOL   Fly_IsEnabled(void);
void   FlyDir_SetEnabled(BOOL en);
BOOL   FlyDir_IsEnabled(void);
UINT64 Fly_GetLpEp(void);
UINT64 Fly_GetPObjDecryptedVA(void);
void   Fly_GetCamTrig(float* cY, float* sY, float* cP, float* sP);
BOOL   Fly_ReadCam(float* yaw, float* pitch, UINT64* camBaseOut);
BOOL   Fly_WriteCam(float yaw, float pitch);
UINT64 Fly_GetCamBase(void);
void   Fly_SetCamPreScanResult(UINT64 va);
void   Fly_SetLpEpPreScanResult(UINT64 va);
void   Fly_SetPObjPreScanResult(UINT64 va);

#ifdef __cplusplus
}
#endif