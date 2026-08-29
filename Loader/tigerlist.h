#pragma once
/* tigerlist.h — PObjects (TigerList) player slot array and bone reader
 *
 * Slot layout (stride TL_STRIDE, up to TL_MAX_SLOTS):
 *   +0x0004  u32  playerDef handle
 *   +0x0084  u32  SObject handle
 *   +0x0A24  u32  team ID
 *   +0x48A0  u32  bone datum handle
 *
 * Bone component (after datum resolve):
 *   +0x0B0  f32[4]  root quaternion
 *   +0x0C0  f32[4]  root position (xyz + pad)
 *   +0x140  i32     bone count
 *   +0x180  bone[]  stride 0x20: +0x00 quat(16) +0x10 pos(12)
 *
 * World bone = quat_rotate(rootQuat, bonePos) + rootPos
 */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SERAPH_MARATHON
#define TL_MAX_SLOTS          32
#define TL_STRIDE             0x7D60ULL
#define TL_OFF_PLAYERDEF_HDL  0x0004u
#define TL_OFF_SOBJECT_HDL    0x0084u
#define TL_OFF_TEAM           0x0120u
#define TL_OFF_BONE_HDL       0x0084u // Bone/SObject handle is at offset 0x84 in Marathon

#define TL_BONE_ROOT_QUAT_OFF 0xB0u
#define TL_BONE_ROOT_POS_OFF  0xC0u
#define TL_BONE_DESC_CNT_OFF  0x140u
#define TL_BONE_DESC_DATA_OFF 0x180u
#define TL_BONE_STRIDE        0x20u
#define TL_BONE_POS_OFF       0x10u
#else
#define TL_MAX_SLOTS          16
#define TL_STRIDE             0x4F20ULL
#define TL_OFF_PLAYERDEF_HDL  0x0004u
#define TL_OFF_SOBJECT_HDL    0x0084u
#define TL_OFF_TEAM           0x0A24u
#define TL_OFF_BONE_HDL       0x48A0u

#define TL_BONE_ROOT_QUAT_OFF 0xB0u
#define TL_BONE_ROOT_POS_OFF  0xC0u
#define TL_BONE_DESC_CNT_OFF  0x140u
#define TL_BONE_DESC_DATA_OFF 0x180u
#define TL_BONE_STRIDE        0x20u
#define TL_BONE_POS_OFF       0x10u
#endif

typedef struct { float x, y, z; } TlVec3;

BOOL   TigerList_Init(void);
BOOL   TigerList_IsReady(void);
void   TigerList_Reset(void);
UINT64 TigerList_GetContainer(void);
BOOL   TigerList_ReadLPPosition(float out[3]);
BOOL   TigerList_ReadLPHeadPosition(float out[3]);
UINT64 TigerList_GetLPHavokRigidBody(void);
/* arrPtr: pre-resolved TigerList array pointer (container+0x08).
 * Pass 0 to let the function resolve it internally (slower — reads container each time).
 * Callers that already have arrPtr (e.g. Skeleton_ReadAll) should always pass it. */
int    TigerList_ReadBones(int slotIndex, UINT64 cr3, UINT64 arrPtr,
                           const float entityWorldPos[3],
                           TlVec3 *outBones, short *outParents, int maxBones,
                           float rootPosOut[3]);

#ifdef __cplusplus
}
#endif