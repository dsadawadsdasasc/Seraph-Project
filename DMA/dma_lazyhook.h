/*
 * dma_lazyhook.h  --  DMA drop-in for lazyhook.h
 *
 * API is identical to lazyhook.h — all callers compile unchanged.
 * The implementation uses DMA_ReadVA/WriteVA in place of BYOVD_ReadVA/WriteVA.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LAZYHOOK_MAX         16
#define LAZYHOOK_MAX_STOLEN  32

typedef struct {
    UINT64 hookVA;
    UINT64 caveVA;
    UINT32 caveUsed;
    UINT8  originalBytes[LAZYHOOK_MAX_STOLEN];
    UINT8  stolenLen;
    BOOL   installed;
} LazyHookEntry;

int  LazyHook_Install(UINT64 cr3,
                      UINT64 hookVA, UINT8 stolenLen,
                      const UINT8 *shellcode, UINT32 shellcodeLen,
                      UINT64 caveVA);

BOOL LazyHook_Remove(int hookId, UINT64 cr3);
void LazyHook_RemoveAll(UINT64 cr3);
void LazyHook_ResetLocalState(void);
const LazyHookEntry *LazyHook_Get(int hookId);
int  LazyHook_Count(void);

#ifdef __cplusplus
}
#endif
