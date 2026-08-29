#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_nja_pat[];
extern const UINT8 k_nja_mask[];

void NoJoinAllies_OnAttach(void);
void NoJoinAllies_OnDetach(void);
int  NoJoinAllies_GetPatchId(void);

/* Pre-scan injection (see revive.h). */
void NoJoinAllies_SetPreScanResult(UINT64 matchVA);

/* Read mailbox + BYOVD-write 0 (8 bytes) to [rdi+0x30]. Idempotent;
 * no-op when the mailbox is empty. */
void NoJoinAllies_TriggerOneShotZero(void);

#ifdef __cplusplus
}
#endif
