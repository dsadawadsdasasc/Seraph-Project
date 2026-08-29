#pragma once
#include <windows.h>
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "aob_patterns.h"

#define HAVOK_MAX_ISLANDS   0x1388u
#define HAVOK_MAX_ENTITIES  256u
#define HAVOK_MAX_RESULTS   256u

#define HAVOK_OFF_ISLAND_LIST0  0x40u
#define HAVOK_OFF_ISLAND_LIST1  0x50u
#define HAVOK_OFF_ENTITY_LIST   0x68u

#define RB_OFF_VTABLE       0x000u
#define RB_OFF_P_HKP_WORLD  0x018u
#define RB_OFF_P_COLLIDABLE 0x020u
#define RB_OFF_ENTITY_DATA  0x150u
#define RB_OFF_P_MOTION     0x150u
#define RB_OFF_COORDS       0x1C0u
#define RB_OFF_VELOCITY     0x230u
#define RB_OFF_ROTATION     0x240u

typedef struct {
    float x, y, z;
} HavokVec3;

typedef struct {
    UINT64 list;
    UINT32 count;
    UINT32 pad;
} IslandListHeader;

typedef struct {
    UINT64   entity_ptr;
    UINT64   vtable;
    UINT64   motion_vtable;
    HavokVec3 coords;
    BOOL     is_local;
    int      list_tag;
    float    speed2;
    float    dist2;
} HavokEntity;

typedef struct {
    UINT64 hkp_world_va;
    UINT64 hkp_world_ptr_va;
    UINT64 hkp_motion_vtable;
    UINT64 local_entity_ptr;
    HavokVec3 local_pos;
    UINT64 reject_vt1;
    UINT64 reject_vt2;
} HavokState;

extern HavokState g_HavokState;
extern HavokVec3 g_camWorldPos;
extern BOOL      g_camWorldPosValid;

static inline void Havok_SetCamPos(float x, float y, float z) {
    g_camWorldPos.x = x; g_camWorldPos.y = y; g_camWorldPos.z = z;
    g_camWorldPosValid = TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_hkp_pat[];
extern const UINT8 k_hkp_mask[];

void Havok_SetHkpPreScanResult(UINT64 va);
BOOL Havok_Init(void);
int  Havok_GetEntities(HavokEntity *out_entities, int max_out);
void Havok_Reset(void);
UINT64 Havok_GetLocalPlayerEp(void);
BOOL Havok_GetLocalPlayerPos(float out[3]);

#ifdef __cplusplus
}
#endif
