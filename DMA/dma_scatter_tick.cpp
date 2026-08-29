/*
 * dma_scatter_tick.cpp  --  Per-frame scatter-read batching.
 *
 * See dma_scatter_tick.h for full design documentation.
 */

#include "dma_scatter_tick.h"
#include "dma_mem.hpp"
#include <windows.h>
#include <cstring>
#include <cstdlib>

/* ── Internal state ─────────────────────────────────────────────────────── */

#define TICK_TRANSIENT_MAX 256   /* max reads in a single transient session */

struct TickRead {
    UINT64  va;
    void   *buf;
    UINT32  size;
};

/* Transient (per-tick inline) reads */
static TickRead s_pending[TICK_TRANSIENT_MAX];
static int      s_pendingN = 0;

/* Static-registration slots (persistent across ticks) */
struct TickSlot {
    UINT64  va;
    void   *buf;
    UINT32  size;
    BOOL    active;
};
static TickSlot s_slots[DMA_TICK_MAX_SLOTS];
static int      s_slotsN = 0;
static CRITICAL_SECTION s_tickCs;
static BOOL s_csInited = FALSE;

static inline void EnsureCs(void) {
    if (!s_csInited) {
        InitializeCriticalSection(&s_tickCs);
        s_csInited = TRUE;
    }
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

/* Execute a list of reads as a scatter batch; fall back to individual reads. */
static BOOL ExecuteReads(TickRead *reads, int n) {
    if (n <= 0) return TRUE;

    /* Micro-yield jitter for timing randomization without 15ms Windows Sleep quantum penalty */
    if ((rand() % 4) == 0) {
        SwitchToThread();
    }

    /* Single read — skip scatter overhead */
    if (n == 1) {
        UINT64 cr3 = DMA_GetCR3();
        return DMA_ReadVA(cr3, reads[0].va, reads[0].buf, reads[0].size);
    }

    /* Batch via scatter API */
    DMA_SCATTER_HANDLE hScat = DMA_ScatterBegin();
    if (!hScat) {
        /* Scatter unavailable — fall back */
        UINT64 cr3 = DMA_GetCR3();
        BOOL ok = TRUE;
        for (int i = 0; i < n; i++)
            if (!DMA_ReadVA(cr3, reads[i].va, reads[i].buf, reads[i].size))
                ok = FALSE;
        return ok;
    }

    for (int i = 0; i < n; i++)
        DMA_ScatterAddRead(hScat, reads[i].va, reads[i].buf, reads[i].size);

    BOOL ok = DMA_ScatterExecute(hScat);
    DMA_ScatterFree(hScat);

    if (!ok) {
        /* Scatter failed — retry individually */
        UINT64 cr3 = DMA_GetCR3();
        ok = TRUE;
        for (int i = 0; i < n; i++)
            if (!DMA_ReadVA(cr3, reads[i].va, reads[i].buf, reads[i].size))
                ok = FALSE;
    }
    return ok;
}

/* ── Transient (inline per-tick) API ────────────────────────────────────── */

void DMA_Tick_Begin(void) {
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    s_pendingN = 0;
    LeaveCriticalSection(&s_tickCs);
}

BOOL DMA_Tick_AddRead(UINT64 va, void *buf, UINT32 size) {
    if (!buf || size == 0 || !va) return FALSE;
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    if (s_pendingN >= TICK_TRANSIENT_MAX) {
        /* Table full — execute what we have, then reset */
        ExecuteReads(s_pending, s_pendingN);
        s_pendingN = 0;
    }
    s_pending[s_pendingN].va   = va;
    s_pending[s_pendingN].buf  = buf;
    s_pending[s_pendingN].size = size;
    s_pendingN++;
    LeaveCriticalSection(&s_tickCs);
    return TRUE;
}

BOOL DMA_Tick_Execute(void) {
    if (!DMA_IsAttached()) return FALSE;
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    BOOL ok = ExecuteReads(s_pending, s_pendingN);
    s_pendingN = 0;
    LeaveCriticalSection(&s_tickCs);
    return ok;
}

/* ── Static-registration (persistent hot reads) ─────────────────────────── */

int DMA_Tick_Register(UINT64 va, void *buf, UINT32 size) {
    if (!buf || size == 0 || !va) return -1;
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    if (s_slotsN >= DMA_TICK_MAX_SLOTS) {
        LeaveCriticalSection(&s_tickCs);
        return -1;
    }
    int idx = s_slotsN++;
    s_slots[idx].va     = va;
    s_slots[idx].buf    = buf;
    s_slots[idx].size   = size;
    s_slots[idx].active = TRUE;
    LeaveCriticalSection(&s_tickCs);
    return idx;
}

void DMA_Tick_UpdateVA(int slot, UINT64 newVA) {
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    if (slot >= 0 && slot < s_slotsN) {
        s_slots[slot].va = newVA;
    }
    LeaveCriticalSection(&s_tickCs);
}

BOOL DMA_Tick_Flush(void) {
    if (!DMA_IsAttached()) return FALSE;
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    if (s_slotsN == 0) {
        LeaveCriticalSection(&s_tickCs);
        return FALSE;
    }

    /* Build a transient read list from active slots */
    static TickRead tmp[DMA_TICK_MAX_SLOTS];
    int n = 0;
    for (int i = 0; i < s_slotsN; i++) {
        if (!s_slots[i].active || !s_slots[i].va) continue;
        tmp[n].va   = s_slots[i].va;
        tmp[n].buf  = s_slots[i].buf;
        tmp[n].size = s_slots[i].size;
        n++;
    }
    BOOL ok = ExecuteReads(tmp, n);
    LeaveCriticalSection(&s_tickCs);
    return ok;
}

void DMA_Tick_ClearSlots(void) {
    EnsureCs();
    EnterCriticalSection(&s_tickCs);
    memset(s_slots, 0, sizeof(s_slots));
    s_slotsN   = 0;
    s_pendingN = 0;
    LeaveCriticalSection(&s_tickCs);
}
