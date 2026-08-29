/*
 * dma_cave_finder.h  --  DMA drop-in for cave_finder.h
 *
 * API is identical to cave_finder.h — all callers compile unchanged.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    UINT64 va;
    UINT32 size;
} CaveInfo;

#define CAVE_MAX_RESULTS 32

int    CaveFinder_Scan(UINT64 cr3, UINT64 moduleBase,
                       UINT32 minSize, CaveInfo *out, int maxOut);

UINT64 CaveFinder_FindFirst(UINT64 cr3, UINT64 moduleBase, UINT32 requiredSize);

UINT64 CaveFinder_FindNear(UINT64 cr3, UINT64 moduleBase,
                            UINT32 requiredSize, UINT64 nearVA);

UINT64 CaveFinder_FindNearNoReserve(UINT64 cr3, UINT64 moduleBase,
                                    UINT32 requiredSize, UINT64 nearVA);

BOOL   CaveFinder_Reserve(UINT64 va, UINT32 size);
void   CaveFinder_ClearReservations(void);

#ifdef __cplusplus
}
#endif
