#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_ntb_pat[];
extern const UINT8 k_ntb_mask[];

void NoTurnBack_OnAttach(void);
void NoTurnBack_OnDetach(void);
int  NoTurnBack_GetPatchId(void);

/* Pre-scan injection (see revive.h). */
void NoTurnBack_SetPreScanResult(UINT64 matchVA);

/* Read mailbox + BYOVD-write 0.0f to [rsi+0x54].  Idempotent; no-op when
 * the mailbox is empty (function hasn't been hit since attach). */
void NoTurnBack_TriggerOneShotZero(void);

#ifdef __cplusplus
}
#endif
