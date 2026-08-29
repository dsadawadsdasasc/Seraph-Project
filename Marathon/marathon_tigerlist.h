#pragma once
/* marathon_tigerlist.h — Marathon TigerList (PlayerObjectArray) specific definitions */

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_MAX_SLOTS          32
#define TL_STRIDE             0x79A0ULL
#define TL_OFF_PLAYERDEF_HDL  0x0004u
#define TL_OFF_SOBJECT_HDL    0x0084u
#define TL_OFF_TEAM           0x0120u
#define TL_OFF_BONE_HDL       0x0084u // SObject handle is at offset 0x84, which we use to find bones

#define TL_BONE_ROOT_QUAT_OFF 0xB0u
#define TL_BONE_ROOT_POS_OFF  0xC0u
#define TL_BONE_DESC_CNT_OFF  0x140u
#define TL_BONE_DESC_DATA_OFF 0x180u
#define TL_BONE_STRIDE        0x20u
#define TL_BONE_POS_OFF       0x10u

BOOL   TigerList_Init(void);
BOOL   TigerList_IsReady(void);
void   TigerList_Reset(void);
UINT64 TigerList_GetContainer(void);
BOOL   TigerList_ReadLPPosition(float out[3]);
BOOL   TigerList_ReadLPHeadPosition(float out[3]);
int    TigerList_ReadBones(int slotIndex, UINT64 cr3, UINT64 arrPtr,
                           const float entityWorldPos[3],
                           TlVec3 *outBones, short *outParents, int maxBones,
                           float rootPosOut[3]);

#ifdef __cplusplus
}
#endif
