/*
 * dma_patch.cpp  --  DMA replacement for patch.c / patch.h
 *
 * Same API as patch.h — every feature file compiles unchanged.
 *
 * Simplifications vs BYOVD patch.c:
 *   - No Themida MUTATE_START/END.
 *   - No write-verify loop on every Patch_Apply — DMA writes go directly to
 *     physical RAM and succeed or fail cleanly; the heavy verify loop was a
 *     BYOVD workaround for occasional driver cache mismatches.
 *   - No per-call BYOVD_LOCK — callers wrap with DMA_LOCK as needed, and
 *     DMA_WriteVA itself is re-entrant.
 */

#include "dma_mem.hpp"
#include "dma_patch.h"    /* canonical PatchEntry + PATCH_MAX_BYTES */
#include "dma_attach.h"   /* GetDestiny2CR3 */
#include <cstring>

/* ── Patch table ────────────────────────────────────────────────────────── */
#define MAX_PATCHES 64

static PatchEntry s_p[MAX_PATCHES];
static int        s_cnt = 0;

/* ── Patch_Register ─────────────────────────────────────────────────────── */
extern "C" int Patch_Register(const char *name, UINT64 va,
                               const UINT8 *bytes, UINT8 len) {
    if (!name || !bytes || !len || len > PATCH_MAX_BYTES || s_cnt >= MAX_PATCHES)
        return -1;

    PatchEntry *e = &s_p[s_cnt];
    memset(e, 0, sizeof(*e));
    e->va  = va;
    e->len = len;
    strncpy(e->name, name, 31);
    memcpy(e->patched, bytes, len);

    /* Pre-read originals now so same-VA patches always have correct backup */
    UINT64 cr3 = GetDestiny2CR3();
    if (cr3 && DMA_ReadVA(cr3, va, e->original, len))
        e->originalLoaded = TRUE;

    return s_cnt++;
}

/* ── Patch_Apply ────────────────────────────────────────────────────────── */
extern "C" BOOL Patch_Apply(int id) {
    if (id < 0 || id >= s_cnt) return FALSE;
    PatchEntry *e = &s_p[id];
    if (e->applied) return TRUE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    /* Lazy-load originals if pre-read failed at Register time */
    if (!e->originalLoaded) {
        if (!DMA_ReadVA(cr3, e->va, e->original, e->len)) return FALSE;
        e->originalLoaded = TRUE;
    }

    if (!DMA_WriteVAPhys(e->va, e->patched, e->len)) return FALSE;
    DMA_RestorePageReadOnly(e->va);
    e->applied = TRUE;
    return TRUE;
}

/* ── Patch_Restore ───────────────────────────────────────────────────── */
extern "C" BOOL Patch_Restore(int id) {
    if (id < 0 || id >= s_cnt) return FALSE;
    PatchEntry *e = &s_p[id];
    if (!e->applied) return TRUE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    if (!DMA_WriteVAPhys(e->va, e->original, e->len)) return FALSE;
    DMA_RestorePageReadOnly(e->va);
    e->applied = FALSE;
    return TRUE;
}

/* ── Remaining API ──────────────────────────────────────────────────────── */
extern "C" BOOL Patch_Toggle(int id) {
    if (id < 0 || id >= s_cnt) return FALSE;
    return s_p[id].applied ? (Patch_Restore(id) ? FALSE : s_p[id].applied)
                           : (Patch_Apply(id)   ? TRUE  : s_p[id].applied);
}

extern "C" BOOL        Patch_IsApplied(int id) { return (id>=0&&id<s_cnt)?s_p[id].applied:FALSE; }
extern "C" const char *Patch_GetName(int id)   { return (id>=0&&id<s_cnt)?s_p[id].name:nullptr; }
extern "C" int         Patch_Count(void)       { return s_cnt; }

extern "C" void Patch_RestoreAll(void) {
    for (int i = 0; i < s_cnt; i++)
        if (s_p[i].applied) Patch_Restore(i);
}

extern "C" void Patch_Reset(void) {
    /* Restore all while CR3 is still valid (called from Attach_Invalidate) */
    UINT64 cr3 = GetDestiny2CR3();
    for (int i = 0; i < s_cnt; i++) {
        if (s_p[i].applied && cr3)
            DMA_WriteVAPhys(s_p[i].va, s_p[i].original, s_p[i].len);
        s_p[i].applied = FALSE;
    }
    memset(s_p, 0, sizeof(s_p));
    s_cnt = 0;
}

extern "C" void Patch_SetBytes(int id, const UINT8 *bytes, UINT8 len) {
    if (id<0||id>=s_cnt||!bytes||!len||len>PATCH_MAX_BYTES) return;
    s_p[id].len = len;
    memcpy(s_p[id].patched, bytes, len);
}

extern "C" PatchEntry *Patch_GetEntry(int id) {
    return (id>=0&&id<s_cnt) ? &s_p[id] : nullptr;
}
