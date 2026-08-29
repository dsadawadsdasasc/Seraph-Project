/* byovd_lock.h -- Global serialization lock for all BYOVD (CtiIo64) operations.
 *
 * The CtiIo64 driver uses a stateful VA->PA cache and per-IOCTL physical
 * mappings that are NOT thread-safe.  Any concurrent call from two threads
 * (e.g. AutoAttachThread doing BYOVD_ScanPattern while the render thread
 * calls GameSpeed_Tick -> BYOVD_WriteVA) corrupts the shared cache and
 * can send an IOCTL to an already-unmapped section handle -> AV / BSOD.
 *
 * ALL callers that touch BYOVD_ReadVA / BYOVD_WriteVA / BYOVD_ScanPattern /
 * BYOVD_FindProcessInfo / BYOVD_FindProcessCR3 MUST hold this lock.
 *
 * Usage:
 *   #include "byovd_lock.h"
 *   BYOVD_LOCK();
 *   ... BYOVD_xxx calls ...
 *   BYOVD_UNLOCK();
 *
 * The lock is initialized in byovd_lock.c (linked into Loader.vcxproj).
 */
#pragma once

#ifdef SERAPH_DMA_BUILD
#include "../DMA/byovd_lock.h"
#else

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern CRITICAL_SECTION g_byovdLock;

/* Initialize once at startup (called from BYOVD_Init) */
void BYOVD_LockInit(void);
void BYOVD_LockDestroy(void);

#define BYOVD_LOCK()        EnterCriticalSection(&g_byovdLock)
#define BYOVD_UNLOCK()      LeaveCriticalSection(&g_byovdLock)
/* Non-blocking try-lock: use in render thread Tick functions so they skip
 * the write if the bg thread is currently doing a scan (avoids UI freeze). */
#define BYOVD_TRYLOCK()     TryEnterCriticalSection(&g_byovdLock)
/* Usage: if(BYOVD_TRYLOCK()){ ... BYOVD_UNLOCK(); } */

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_DMA_BUILD */
