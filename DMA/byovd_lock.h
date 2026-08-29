/*
 * byovd_lock.h  --  DMA build compatibility stub.
 *
 * Shadows Loader/byovd_lock.h.  The BYOVD version needed a CRITICAL_SECTION
 * because CtiIo64's IOCTL cache was not re-entrant.  DMA has no such
 * restriction: each ReadRaw/WriteRaw is an independent PCIe transaction and
 * the VMMDLL handle is protected by g_dmaLock (std::mutex in dma_mem.hpp).
 *
 * BYOVD_LOCK / BYOVD_UNLOCK / BYOVD_TRYLOCK are already defined in
 * dma_mem.hpp (redirect to DMA_LOCK / DMA_UNLOCK / DMA_TRYLOCK).
 * We just suppress the CRITICAL_SECTION declaration that the original
 * byovd_lock.h emits.
 */
#pragma once

/* Include dma_mem.hpp BEFORE extern "C" — it pulls in <mutex> which
 * contains C++ templates that cannot have C linkage. */
#include "dma_mem.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/* No-op init/destroy — std::mutex needs no explicit call */
static __inline void BYOVD_LockInit(void)    { (void)0; }
static __inline void BYOVD_LockDestroy(void) { (void)0; }

#ifdef __cplusplus
}
#endif
