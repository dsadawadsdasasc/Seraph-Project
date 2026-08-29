/*
 * dma_attach.h  --  DMA version of attach.h
 *
 * Exposes the same interface as the BYOVD attach.h so every feature file
 * compiles without changes.  Implementation uses DMA_Reattach internally.
 */
#pragma once
#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Drop-in replacements for the BYOVD attach API */
BOOL   Destiny2ProcessFound(void);
BOOL   AttachToDestiny2(void);
UINT64 GetDestiny2CR3(void);
UINT64 GetDestiny2Base(void);
UINT64 GetDestiny2PEB(void);
void   Attach_Invalidate(void);

/* AutoAttach polling thread (same signature as BYOVD build) */
void   StartAutoAttach(void);

#ifdef __cplusplus
}
#endif
