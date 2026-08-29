#pragma once
#include "byovd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_silent_pat[];
extern const UINT8 k_silent_mask[];

void SilentAim_SetPreScanResult(UINT64 va);
void SilentAim_OnAttach(void);
void SilentAim_OnDetach(void);
BOOL SilentAim_IsReady(void);
BOOL SilentAim_IsEnabled(void);
void SilentAim_SetEnabled(BOOL state);

/* ── Configurable magnetism ──────────────────────────────────────────────── *
 * Sets the cone angle value stored in the cave (seen by the shellcode at
 * cave+0x08).  Written to game memory on next SetEnabled(TRUE).               */
void SilentAim_SetMagnetism(float coneDeg);

/* Diagnostic: read shellcode spy counters
 *   out_count  - number of shellcode invocations since enable
 *   out_marker - last [base-0x48] float seen (for layout discovery)
 * Returns FALSE if hook not installed or BYOVD read fails. */
BOOL SilentAim_ReadSpy(UINT32 *out_count, float *out_marker);

#ifdef __cplusplus
}
#endif
