/*
 * antire_handles.h  --  DMA build: handle-watcher stub (all no-ops).
 *
 * Shadows Loader/antire_handles.h.  The handle-watcher (P6.2) monitors
 * whether another process has opened a dangerous handle to OUR process or
 * to Destiny 2.  On the DMA machine OUR process is invisible to BattleEye,
 * so this protection is unnecessary.  All functions are no-ops.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*AntiRE_HotRevertFn)(void);

static __inline void AntiRE_Handles_Start      (DWORD ourPid)          { (void)ourPid; }
static __inline void AntiRE_Handles_SetD2Pid   (DWORD d2Pid)           { (void)d2Pid;  }
static __inline void AntiRE_Handles_Stop       (void)                   { (void)0;      }
static __inline void AntiRE_Handles_SetHotRevert(AntiRE_HotRevertFn fn){ (void)fn;      }

#ifdef __cplusplus
}
#endif
