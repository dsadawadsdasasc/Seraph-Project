#include "monster_skeleton.h"
#include "sobject.h"
#include "sobject_list.h"
#include "byovd.h"
#include <string.h>

MonsterSkeletonState g_MonsterSkelState = {0};

/* ── Fallback / Package Extracted Bone Parent Hierarchies ──────────────────── */

/* Expanded Bone Parent Hierarchies for all Destiny 2 Rig Classes */

/* 22 Bones (Shanks / Small Harpies / Small Props) */
static const int16_t PARENTS_22[22] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18
};

/* 24 Bones (Psions / Thralls / Small Vex Goblins) */
static const int16_t PARENTS_24[24] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
};

/* 25 Bones (Standard Bipedal Humanoid - Players, Acolytes, Vandals, Legionnaires) */
static const int16_t PARENTS_25[25] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 11, 11, 11, 12, 13, 14, 16, 15, 17, 19, 20, 21, 22
};

/* 27-28 Bones (Knights, Minotaurs, Captains) */
static const int16_t PARENTS_27[27] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 11, 11, 11, 12, 13, 14, 16, 15, 17, 19, 20, 21, 22, 23, 24
};

/* 30 Bones (Heavy Captains / Servitors / Ogres) */
static const int16_t PARENTS_30[30] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 11, 11, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26
};

/* 32-35 Bones (Wyverns / Tormentors / Centurions / Gladiators) */
static const int16_t PARENTS_32[32] = {
    -1, 0, 0, 1, 1, 1, 3, 4, 5, 6, 7, 8, 11, 11, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
};

/* Generic sequential fallback: bone[i] connects to bone[i-1] */
static int16_t s_generic_parents[MONSTER_MAX_BONES];
static BOOL    s_generic_inited = FALSE;

static void InitGenericParents(void) {
    if (s_generic_inited) return;
    s_generic_parents[0] = -1;
    for (int i = 1; i < MONSTER_MAX_BONES; i++) {
        s_generic_parents[i] = (int16_t)(i - 1);
    }
    s_generic_inited = TRUE;
}

const int16_t* Monster_GetParentHierarchy(int bone_count, uint32_t schema_h) {
    (void)schema_h;

    switch (bone_count) {
        case 22: return PARENTS_22;
        case 24: return PARENTS_24;
        case 25: return PARENTS_25;
        case 27:
        case 28: return PARENTS_27;
        case 30: return PARENTS_30;
        case 32:
        case 33:
        case 35: return PARENTS_32;
        default:
            InitGenericParents();
            return s_generic_parents;
    }
}

void MonsterSkeleton_Init(void) {
    if (g_MonsterSkelState.initialized) return;
    InitializeCriticalSection(&g_MonsterSkelState.lock);
    g_MonsterSkelState.count = 0;
    g_MonsterSkelState.initialized = TRUE;
}

void MonsterSkeleton_Cleanup(void) {
    if (!g_MonsterSkelState.initialized) return;
    DeleteCriticalSection(&g_MonsterSkelState.lock);
    g_MonsterSkelState.count = 0;
    g_MonsterSkelState.initialized = FALSE;
}

/* Helper context for walking component chain */
typedef struct {
    UINT64 cr3;
    UINT64 boneCompVA;
    int    boneCount;
    uint32_t schemaHash;
} BoneCompFindCtx;

static void BoneCompCallback(UINT64 node_va, void *user_ctx) {
    BoneCompFindCtx *ctx = (BoneCompFindCtx*)user_ctx;
    if (ctx->boneCompVA != 0) return; /* Already found */

    int bc = SObjectList_ReadBoneCount(ctx->cr3, node_va);
    if (bc > 0 && bc <= MONSTER_MAX_BONES) {
        ctx->boneCompVA = node_va;
        ctx->boneCount = bc;
        /* Read schema hash for potential schema disambiguation */
        BYOVD_LOCK();
        BYOVD_ReadVA(ctx->cr3, node_va + SOBJ_COMP_OFF_SCHEMA_H, &ctx->schemaHash, 4);
        BYOVD_UNLOCK();
    }
}

void MonsterSkeleton_Update(void) {
    if (!g_MonsterSkelState.initialized) {
        MonsterSkeleton_Init();
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !SObjectList_IsReady()) return;

    MonsterEntity tempEntities[MONSTER_MAX_ENTITIES];
    int tempCount = 0;

    /* Iterate SObject entries */
    UINT32 maxSlots = SObjectList_GetMaxCount();
    if (maxSlots > SOBJ_MAX_COUNT) maxSlots = SOBJ_MAX_COUNT;

    for (UINT32 i = 0; i < maxSlots && tempCount < MONSTER_MAX_ENTITIES; i++) {
        SObjectRaw raw;
        if (!SObjectList_ReadEntity(i, &raw)) continue;

        /* Filter strictly for PvE Enemies */
        if (!SObject_IsPvEEnemy(raw.type_flags, raw.type)) continue;
        if (!raw.alive) continue;

        /* Decrypt world position */
        float worldPos[3];
        if (!SObjectList_DecryptPosition(raw.componentToWorld.enc_pos, 0, worldPos)) continue;

        /* Find bone component in component chain (+0x4C) */
        if (raw.comp_handle == 0 || raw.comp_handle == 0xFFFFFFFFu) continue;

        BoneCompFindCtx ctx = {0};
        ctx.cr3 = cr3;
        SObjectList_WalkComponents(cr3, raw.comp_handle, BoneCompCallback, &ctx);

        if (!ctx.boneCompVA || ctx.boneCount <= 0) continue;

        /* Read bone positions */
        float flatBones[MONSTER_MAX_BONES * 3];
        int readBones = SObjectList_ReadBones(cr3, ctx.boneCompVA, flatBones, ctx.boneCount);
        if (readBones <= 0) continue;

        /* Populate entity record */
        MonsterEntity *m = &tempEntities[tempCount];
        m->handle = raw.objectHandle;
        m->type_flags = raw.type_flags;
        m->type = raw.type;
        m->alive = raw.alive;
        m->rootPos[0] = worldPos[0];
        m->rootPos[1] = worldPos[1];
        m->rootPos[2] = worldPos[2];
        m->boneCount = (uint32_t)readBones;

        for (int b = 0; b < readBones; b++) {
            m->bones[b][0] = flatBones[b * 3 + 0];
            m->bones[b][1] = flatBones[b * 3 + 1];
            m->bones[b][2] = flatBones[b * 3 + 2];
        }

        /* Retrieve parent hierarchy */
        const int16_t *parents = Monster_GetParentHierarchy(readBones, ctx.schemaHash);
        for (int b = 0; b < readBones; b++) {
            m->boneParents[b] = parents[b];
        }

        tempCount++;
    }

    /* Thread-safe swap to global state */
    EnterCriticalSection(&g_MonsterSkelState.lock);
    g_MonsterSkelState.count = tempCount;
    memcpy(g_MonsterSkelState.entities, tempEntities, sizeof(MonsterEntity) * tempCount);
    LeaveCriticalSection(&g_MonsterSkelState.lock);
}
