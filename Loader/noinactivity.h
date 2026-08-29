#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* No Inactivity — port of CE script "inactivity_kick_flag".
 *
 *   AOB:   48 8D 2D ?? ?? ?? ?? 48 63 C7   (10 bytes, unique)
 *          lea rcx, [rip+disp32]   ; loads flag-struct base
 *          movsxd rax, edi         ; index follow-up
 *
 *   Resolve:
 *     leaTarget = matchVA + 7 + *(int32*)(matchVA + 3)
 *     flagVA    = leaTarget + 8
 *
 * The flag at flagVA drives the AFK/inactivity kick.  Writing 0 to it
 * keeps the player from being kicked for inactivity.  Implemented as a
 * standard Patch_Register zero-write on flagVA — toggles via the MISC
 * tab like NoTurnBack / NoJoinAllies.                                   */

extern const UINT8 k_noact_pat[];
extern const UINT8 k_noact_mask[];

void NoInactivity_OnAttach(void);
void NoInactivity_OnDetach(void);
int  NoInactivity_GetPatchId(void);

/* Pre-scan injection (consumed by the multi-scan in gui_core.cpp; optional). */
void NoInactivity_SetPreScanResult(UINT64 matchVA);

#ifdef __cplusplus
}
#endif
