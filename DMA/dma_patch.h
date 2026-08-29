/*
 * dma_patch.h  --  DMA drop-in header for patch.c / patch.h
 *
 * API is identical to Loader/patch.h — all callers compile unchanged.
 * Implementation is in dma_patch.cpp.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum bytes per patch entry (must match Loader/patch.h) */
#define PATCH_MAX_BYTES 32

/* Single patch descriptor — layout identical to Loader/patch.h */
typedef struct {
    UINT64  va;
    UINT8   original[PATCH_MAX_BYTES];
    UINT8   patched [PATCH_MAX_BYTES];
    UINT8   len;
    BOOL    applied;
    BOOL    originalLoaded;
    char    name[32];
} PatchEntry;

/* Register a patch (copies name/va/bytes, does not apply yet).
 * Returns patch ID (0-based index) or -1 on failure. */
int  Patch_Register(const char *name, UINT64 va, const UINT8 *patchBytes, UINT8 len);

/* Apply / restore a single patch by ID. */
BOOL Patch_Apply  (int id);
BOOL Patch_Restore(int id);

/* Toggle: if applied → restore, else → apply. Returns new applied state. */
BOOL Patch_Toggle(int id);

/* Query */
BOOL            Patch_IsApplied(int id);
const char     *Patch_GetName  (int id);
int             Patch_Count    (void);

/* Restore all applied patches (call on shutdown / detach). */
void Patch_RestoreAll(void);

/* Reset all registrations (call before re-attach to avoid duplication). */
void Patch_Reset(void);

/* Overwrite pending patch bytes without re-applying. */
void Patch_SetBytes(int id, const UINT8 *bytes, UINT8 len);

/* Direct pointer access for advanced manipulation (crash recovery). */
PatchEntry *Patch_GetEntry(int id);

#ifdef __cplusplus
}
#endif
