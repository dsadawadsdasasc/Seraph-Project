#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_hrg_pat[];
extern const UINT8 k_hrg_mask[];
void HealthRegen_SetPreScanResult(UINT64 va);

/* Called from AutoAttachThread after game is attached.
 * Scans for the jbe pattern and registers the jmp patch. */
void HealthRegen_OnAttach(void);

/* Called from Attach_Invalidate when game process dies. */
void HealthRegen_OnDetach(void);

/* Returns the Patch_Register ID for this feature, or -1 if not ready.
 * The ID integrates with the existing g_patchActive[] toggle system. */
int  HealthRegen_GetPatchId(void);

#ifdef __cplusplus
}
#endif
