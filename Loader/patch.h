#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum bytes per patch entry */
#define PATCH_MAX_BYTES 32

/* Single patch descriptor */
typedef struct {
    UINT64  va;                         /* virtual address in target process  */
    UINT8   original[PATCH_MAX_BYTES];  /* saved original bytes               */
    UINT8   patched [PATCH_MAX_BYTES];  /* bytes to write on apply            */
    UINT8   len;                        /* number of bytes                    */
    BOOL    applied;                    /* TRUE if currently patched          */
    BOOL    originalLoaded;             /* TRUE if original[] was successfully pre-read */
    char    name[32];                   /* label shown in menu                */
} PatchEntry;

/* Register a patch (copies name/va/bytes, does not apply yet).
 * Returns patch ID (0-based index) or -1 on failure. */
int  Patch_Register(const char *name, UINT64 va, const UINT8 *patchBytes, UINT8 len);

/* Apply / restore a single patch by ID. Saves original bytes on first apply.
 * Uses s_d2CR3 from attach module — call after AttachToDestiny2 succeeds.  */
BOOL Patch_Apply  (int id);
BOOL Patch_Restore(int id);

/* Toggle: if applied → restore, if not → apply. Returns new applied state. */
BOOL Patch_Toggle(int id);

/* Returns TRUE if patch[id] is currently applied */
BOOL Patch_IsApplied(int id);

/* Returns name string for patch[id], NULL if invalid */
const char *Patch_GetName(int id);

/* Total registered patches */
int  Patch_Count(void);

/* Restore all applied patches (call on shutdown) */
void Patch_RestoreAll(void);

/* Periodic re-verify + re-apply of active patches.  Call from render loop.
 * Re-applies any patch whose bytes no longer match the expected patched[]
 * sequence, fixing Godmode/Ghostmode randomly deactivating. */
void Patch_Tick(void);

/* Reset all patch registrations (call before re-attach to avoid duplication) */
void Patch_Reset(void);

/* Overwrite the pending patch bytes for next Patch_Apply (does not re-apply if already applied) */
void Patch_SetBytes(int id, const UINT8 *bytes, UINT8 len);

/* Get direct pointer to patch entry for advanced manipulation (crash recovery).
 * Returns NULL if id is invalid. */
PatchEntry *Patch_GetEntry(int id);

#ifdef __cplusplus
}
#endif
