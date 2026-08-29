#pragma once
#include <windows.h>
/* d2_patches.h -- Destiny 2 byte patch definitions
 *
 * HOW TO USE:
 *   1. Find the offset via IDA/Ghidra relative to destiny2.exe base.
 *   2. Call D2Patches_Register() once after AttachToDestiny2() succeeds.
 *   3. Each patch appears as a toggle button in the DEV tab.
 *
 * Offsets are relative to ImageBaseAddress (destiny2.exe base).
 * At runtime:  VA = d2Base + offset
 *
 * FORMAT: D2PATCH(name, offset, patch_bytes...)
 */

#ifdef __cplusplus
extern "C" {
#endif

void D2Patches_Register(void);
/* Returns the menu tab index (1=MISC, 3=DEV, 4=PLAYER) for a given Patch_Register id */
int  D2Patches_GetTabForId(int patchId);
/* External modules register their patch into the tab system after Patch_Register */
void D2Patches_SetExternalTabForId(int patchId, int tab);
/* Returns mutex group (0=independent, >0=mutually exclusive within same group) */
int  D2Patches_GetMutexGroup(int patchId);
/* Returns the number of patches that failed AOB scan during the last
 * D2Patches_Register() call.  0 means every patch landed. */
int  D2Patches_GetFailCount(void);
int  D2Patches_GetNoHealthSoundPatchId(void);
void D2Patches_TriggerNoHealthSoundOneShot(void);
void D2Patches_TriggerNoTimersZero(void);


#ifdef __cplusplus
}
#endif
