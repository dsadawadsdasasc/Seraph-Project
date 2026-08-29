#ifndef MONSTER_SKELETON_H
#define MONSTER_SKELETON_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MONSTER_MAX_BONES    256
#define MONSTER_MAX_ENTITIES 128

typedef struct {
    uint32_t handle;
    float    rootPos[3];
    uint32_t boneCount;
    float    bones[MONSTER_MAX_BONES][3];
    int16_t  boneParents[MONSTER_MAX_BONES];
    uint8_t  type_flags;
    uint8_t  type;
    BOOL     alive;
} MonsterEntity;

/* Global state for active monster skeletons */
typedef struct {
    MonsterEntity entities[MONSTER_MAX_ENTITIES];
    int           count;
    CRITICAL_SECTION lock;
    BOOL          initialized;
} MonsterSkeletonState;

extern MonsterSkeletonState g_MonsterSkelState;

/* Initialization & Cleanup */
void MonsterSkeleton_Init(void);
void MonsterSkeleton_Cleanup(void);

/* Update thread/routine to scan SObject list and update monster skeletons */
void MonsterSkeleton_Update(void);

/* Retrieve parent array mapping for a given bone_count & schema hash */
const int16_t* Monster_GetParentHierarchy(int bone_count, uint32_t schema_h);

#ifdef __cplusplus
}
#endif

#endif /* MONSTER_SKELETON_H */
