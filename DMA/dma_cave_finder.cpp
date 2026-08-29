/*
 * dma_cave_finder.cpp  --  DMA replacement for cave_finder.c
 *
 * Key improvement over BYOVD cave_finder.c:
 *   - The original scans 4 KB at a time, each page its own BYOVD_ReadVA call
 *     (~12 500 round-trips for a 50 MB .text section).
 *   - This version reads 1 MB per DMA call — the same SCAN_CHUNK as the
 *     pattern scanner — reducing round-trips to ~50.
 *   - PE header parsing is delegated to dma_mem.hpp's DMA_GetTextBounds()
 *     which already reads and caches section data.
 *
 * Dropped vs BYOVD:
 *   - All BYOVD_LOCK / BYOVD_UNLOCK calls.
 *   - MUTATE_START / VM_START obfuscation macros.
 *   - Per-page DEBUG_CAVE logging (catastrophically slow for 12 500 pages).
 */

#include "dma_cave_finder.h"
#include "dma_mem.hpp"
#include <cstring>
#include <algorithm>




/* ── Reservation table ──────────────────────────────────────────────────── */
#define CAVE_MAX_RESERVATIONS 64
struct CaveReserv { UINT64 va; UINT32 size; };
static CaveReserv s_rsv[CAVE_MAX_RESERVATIONS];
static int        s_rsvN = 0;



static bool IsReserved(UINT64 va, UINT32 sz) {
    for (int i = 0; i < s_rsvN; i++) {
        UINT64 ra = s_rsv[i].va, rb = ra + s_rsv[i].size;
        UINT64 qa = va,          qb = va + sz;
        if (qa < rb && qb > ra) return true;
    }
    return false;
}

/* ── Insertion sort: largest first ─────────────────────────────────────── */
static void SortCaves(CaveInfo *arr, int n) {
    for (int i = 1; i < n; i++) {
        CaveInfo tmp = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j].size < tmp.size) { arr[j+1] = arr[j]; j--; }
        arr[j+1] = tmp;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  CaveFinder_Scan  —  Vanish-style 64 KB chunked scan
 *
 *  64 KB chunks (same as Vanish’s CodeCaveManager::FindPattern).
 *  A single unreadable page wastes at most 64 KB instead of 1 MB.
 *  Failed chunks are silently skipped — no ZEROPAD, no write-verify.
 * ══════════════════════════════════════════════════════════════ */
static constexpr UINT32 CF_CHUNK = 64u << 10; /* 64 KB — same as Vanish */

extern "C" int CaveFinder_Scan(UINT64 cr3, UINT64 moduleBase,
                                UINT32 minSize, CaveInfo *out, int maxOut)
{
    if (!out || maxOut <= 0 || minSize < 5) return 0;

    /* Delegate section lookup to dma_mem's cached section table */
    UINT64 textVA = 0, textLen = 0;
    if (!DMA_GetTextBounds(cr3, moduleBase, &textVA, &textLen)) return 0;

    /* Working buffer — 64 KB + max cave size for cross-boundary detection */
    static thread_local UINT8 buf[CF_CHUNK + 256];

    int    found    = 0;
    UINT32 runStart = 0, runLen = 0;
    BOOL   inRun    = FALSE;

    for (UINT64 off = 0; off < textLen && found < maxOut; ) {
        UINT32 chunk = (UINT32)(std::min)((UINT64)CF_CHUNK, textLen - off);
        /* ZEROPAD: unreadable pages become 0x00.  Since we only match 0xCC,
         * zero-padded regions are naturally excluded. */
        DMA_ReadVAPad(textVA + off, buf, chunk);

        for (UINT32 i = 0; i < chunk; i++) {
            if (buf[i] == 0xCC) {
                if (!inRun) {
                    runStart = (UINT32)(off + i);
                    runLen   = 1;
                    inRun    = TRUE;
                } else {
                    runLen++;
                }
            } else {
                if (inRun) {
                    if (runLen >= minSize && found < maxOut) {
                        out[found].va   = textVA + runStart;
                        out[found].size = runLen;
                        found++;
                    }
                    inRun = FALSE;
                    runLen = 0;
                }
            }
        }
        off += chunk;
    }

    /* Flush trailing run (outside loop — only after all chunks are done) */
    if (inRun && runLen >= minSize && found < maxOut) {
        out[found].va   = textVA + runStart;
        out[found].size = runLen;
        found++;
    }

    SortCaves(out, found);
    return found;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Convenience wrappers
 * ══════════════════════════════════════════════════════════════════════════ */
extern "C" UINT64 CaveFinder_FindFirst(UINT64 cr3, UINT64 mod, UINT32 req) {
    CaveInfo caves[CAVE_MAX_RESULTS];
    int n = CaveFinder_Scan(cr3, mod, req, caves, CAVE_MAX_RESULTS);
    for (int i = 0; i < n; i++) {
        if (caves[i].size < req) continue;
        if (IsReserved(caves[i].va, caves[i].size)) continue;
        CaveFinder_Reserve(caves[i].va, caves[i].size);
        return caves[i].va;
    }
    return 0;
}

extern "C" UINT64 CaveFinder_FindNearNoReserve(UINT64 cr3, UINT64 mod,
                                                UINT32 req, UINT64 nearVA)
{
    CaveInfo caves[CAVE_MAX_RESULTS];
    int n = CaveFinder_Scan(cr3, mod, req, caves, CAVE_MAX_RESULTS);
    UINT64 best = 0; UINT64 bestDist = ~0ULL;
    for (int i = 0; i < n; i++) {
        if (caves[i].size < req) continue;
        if (IsReserved(caves[i].va, req)) continue;
        INT64 delta = (INT64)caves[i].va - (INT64)nearVA;
        if (delta < -0x7FFFFFFFLL || delta > 0x7FFFFFFFLL) continue;
        UINT64 dist = (UINT64)(delta < 0 ? -delta : delta);
        if (dist < bestDist) { bestDist = dist; best = caves[i].va; }
    }
    return best;
}

extern "C" UINT64 CaveFinder_FindNear(UINT64 cr3, UINT64 mod,
                                       UINT32 req, UINT64 nearVA)
{
    UINT64 va = CaveFinder_FindNearNoReserve(cr3, mod, req, nearVA);
    if (va) CaveFinder_Reserve(va, req);
    return va;
}

extern "C" BOOL CaveFinder_Reserve(UINT64 va, UINT32 size) {
    if (s_rsvN >= CAVE_MAX_RESERVATIONS) return FALSE;
    s_rsv[s_rsvN++] = { va, size };
    return TRUE;
}

extern "C" void CaveFinder_ClearReservations(void) {
    s_rsvN = 0;
    memset(s_rsv, 0, sizeof(s_rsv));
}
