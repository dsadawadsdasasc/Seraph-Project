/*
 * antire.h  --  DMA build: AntiRE stub (all no-ops).
 *
 * Shadows Loader/antire.h.  In the DMA build the cheat binary executes on
 * the OPERATOR'S machine — BattleEye, Cheat Engine, and other RE tools on
 * the VICTIM'S machine have zero visibility into this process.  There is
 * therefore no need to monitor for reverse-engineering handles or tool
 * presence: the entire AntiRE subsystem is a no-op for DMA.
 *
 * The declarations are kept so gui.c compiles without changes.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void AntiRE_Start(void);
void AntiRE_Stop (void);

#ifdef __cplusplus
}
#endif
