#pragma once

#ifdef SERAPH_DMA_BUILD
#include "../DMA/antire.h"
#else

#include <windows.h>

/* Anti-RE monitoring thread.
 * Checks for reverse engineering tools every ~3 seconds.
 * In RELEASE builds (NDEBUG): bans key + dejects + exits after 30s delay.
 * In DEBUG builds: logs detection only (no ban, no exit). */
void AntiRE_Start(void);
void AntiRE_Stop(void);

#endif /* SERAPH_DMA_BUILD */
