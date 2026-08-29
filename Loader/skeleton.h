#pragma once
/* skeleton.h — TigerList-based skeleton ESP
 *
 * Uses TigerList (PObjects array, stride 0x4F20) for bone handles,
 * resolves via datum_resolve, reads FTransform bone array.
 * Transforms are in mesh space; add entity world pos for world space.
 * Entity world positions come from SL (Schindler's List).
 */

#include <windows.h>
#include "tigerlist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SKEL_ENTITY_MAX  16
#define SKEL_BONE_MAX    150

typedef struct {
    UINT32  slotIndex;
    BOOL    isLocalPlayer;
    INT32   team;
    float   worldPos[3];
    BOOL    worldPosValid;
    float   rootPos[3];
    UINT32  boneCount;
    TlVec3  bones[SKEL_BONE_MAX];
    short   boneParents[SKEL_BONE_MAX];
    float   health;   /* 0.0 – 1.0 (normalised), -1.0 if unavailable */
    float   shield;   /* 0.0 – 1.0 (normalised), -1.0 if unavailable */
    char    name[64]; /* Gamertag string */
} SkelEntity;

/* Read all player skeletons. Returns entity count. */
int Skeleton_ReadAll(SkelEntity *out, int max);

/* Thread-safe cached snapshot for overlay. */
int Skeleton_GetCached(SkelEntity *out, int max);

/* Start / stop background update thread (paired with EspOverlay_Start/Stop). */
void Skeleton_StartUpdateThread(void);
void Skeleton_StopUpdateThread(void);

/* Cached view/proj matrices. */
BOOL Skeleton_GetCachedMatrices(float view[16], float proj[16]);

/* Expose local player root bone position cached by the ESP skeleton update thread. */
BOOL Skeleton_GetCachedLPRootPos(float out[3]);
BOOL Skeleton_GetCachedLPHeadPos(float out[3]);
BOOL Skeleton_SlotHasBones(int slotIndex);

#ifdef __cplusplus
}
#endif