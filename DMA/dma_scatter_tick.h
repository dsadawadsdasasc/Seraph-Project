/*
 * dma_scatter_tick.h  --  Per-frame scatter-read batching (DMA advantage).
 *
 * KEY DMA OPTIMIZATION:
 *   Without scatter: each DMA_ReadVA() is an independent PCIe transaction.
 *   N feature reads per tick = N round-trips (~µs each).
 *
 *   With scatter: all N reads are batched into ONE PCIe DMA transaction.
 *   N feature reads per tick = 1 round-trip regardless of N.
 *
 * USAGE PATTERN (opt-in per feature):
 *
 *   // In Feature_OnAttach():
 *   static float s_health = 0.f;
 *   s_health_slot = DMA_Tick_Register(healthVA, &s_health, sizeof(float));
 *
 *   // In Feature_Tick():
 *   DMA_Tick_Flush();          // call once per "master tick" in gui_core.cpp
 *   float hp = s_health;       // value filled by last Flush
 *
 * ALTERNATIVE INLINE USAGE (for hot loops):
 *
 *   DMA_Tick_Begin();                          // clear accumulated reads
 *   DMA_Tick_AddRead(va1, &buf1, size1);       // enqueue N reads
 *   DMA_Tick_AddRead(va2, &buf2, size2);
 *   DMA_Tick_Execute();                        // ONE scatter → fills all bufs
 *
 * THREAD SAFETY:
 *   DMA_Tick_Begin/Execute are NOT thread-safe. Call from a single tick thread.
 *   The static-registration path (DMA_Tick_Register) is initialized from
 *   OnAttach (single-threaded) and read from a single tick thread. Safe.
 *
 * FALLBACK:
 *   If the FPGA scatter fails, each entry is re-read individually so the
 *   feature degrades gracefully to single-read mode.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Inline scatter session (per-tick transient use) ────────────────────── */

/* Start a new transient scatter session (clears accumulated reads). */
void DMA_Tick_Begin(void);

/* Add a VA read to the pending scatter batch (does not execute yet).
 * buf must remain valid until DMA_Tick_Execute() returns. */
BOOL DMA_Tick_AddRead(UINT64 va, void *buf, UINT32 size);

/* Execute all pending reads in one FPGA transaction.
 * Falls back to individual DMA_ReadVA calls on scatter failure. */
BOOL DMA_Tick_Execute(void);

/* ── Static-registration path (persistent per-attach hot reads) ─────────── */
#define DMA_TICK_MAX_SLOTS 128

/* Register a VA to be refreshed on every DMA_Tick_Flush() call.
 * Returns slot index (0..DMA_TICK_MAX_SLOTS-1) or -1 on full table.
 * Call from OnAttach (before tick loop starts). */
int  DMA_Tick_Register(UINT64 va, void *buf, UINT32 size);

/* Update the VA for an existing slot (call if pointer changes after re-attach). */
void DMA_Tick_UpdateVA(int slot, UINT64 newVA);

/* Execute all registered slots in one scatter call.
 * Call once at the top of the master tick loop (before Feature_Tick calls). */
BOOL DMA_Tick_Flush(void);

/* Clear all registered slots (call on Attach_Invalidate / detach). */
void DMA_Tick_ClearSlots(void);

#ifdef __cplusplus
}
#endif
