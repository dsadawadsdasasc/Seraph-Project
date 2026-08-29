#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Infinite Magazine — direct NOP patch approach.
 * AOB: "41 2B D5 49 8B CE E8 ?? ?? ?? ??"
 * Patches first 3 bytes (41 2B D5) with 0F 1F 00 (3-byte NOP).
 */
#ifndef SERAPH_DMA_BUILD


void InfiniteAmmo_SetPreScanResult(UINT64 va);
void InfiniteAmmo_OnAttach(void);
void InfiniteAmmo_OnDetach(void);
void InfiniteAmmo_SetEnabled(BOOL state);
BOOL InfiniteAmmo_IsEnabled(void);
BOOL InfiniteAmmo_IsReady(void);
#else
static inline void InfiniteAmmo_SetPreScanResult(UINT64 va) { (void)va; }
static inline void InfiniteAmmo_OnAttach(void) {}
static inline void InfiniteAmmo_OnDetach(void) {}
static inline void InfiniteAmmo_SetEnabled(BOOL state) { (void)state; }
static inline BOOL InfiniteAmmo_IsEnabled(void) { return FALSE; }
static inline BOOL InfiniteAmmo_IsReady(void) { return FALSE; }
#endif

#ifdef __cplusplus
}
#endif
