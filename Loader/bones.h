#pragma once
/* bones.h — Key bone indices (head, neck, chest, pelvis) mapping for all skeletons. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int head;
    int neck;
    int chest;
    int pelvis;
} BoneHierarchyMap;

/* Retrieve key bone indices based on the active bone count of the entity */
BoneHierarchyMap Bones_GetIndices(int boneCount);

#ifdef __cplusplus
}
#endif

