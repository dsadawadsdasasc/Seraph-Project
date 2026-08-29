/*
 * dma_lazyhook.cpp  --  DMA replacement for lazyhook.c
 *
 * Drops vs BYOVD:
 *   - No BYOVD_LOCK / BYOVD_UNLOCK — DMA_WriteVA is re-entrant and
 *     non-stateful (each call is an independent PCIe transaction).
 *   - No write-verify loop after cave write — not needed with DMA because
 *     the card writes directly to DRAM; there is no driver page cache to
 *     re-issue against.
 *   - No MUTATE_START / VM_START — Themida macros are irrelevant on the
 *     DMA machine (different binary, not shipped to end users).
 *
 * Performance: Cave + hook-patch are two DMA write calls (< 512 + 32 bytes
 * each) — essentially free in terms of latency.  No benefit from scatter
 * here since the writes are sequential by design (cave must exist before
 * the hook JMP redirects execution).
 */

#include "dma_lazyhook.h"
#include "dma_mem.hpp"
#include "debug.h"
#include "seraph_ptr_crypt.h"
#include <cstring>

static LazyHookEntry s_hooks[LAZYHOOK_MAX];
static int           s_count = 0;

/* ── Multi-byte NOP generator (Intel SDM encodings) ────────────────────── */
static void FillMultiByteNop(UINT8 *buf, UINT32 len) {
    static const UINT8 nop1[] = {0x90};
    static const UINT8 nop2[] = {0x66,0x90};
    static const UINT8 nop3[] = {0x0F,0x1F,0x00};
    static const UINT8 nop4[] = {0x0F,0x1F,0x40,0x00};
    static const UINT8 nop5[] = {0x0F,0x1F,0x44,0x00,0x00};
    static const UINT8 nop6[] = {0x66,0x0F,0x1F,0x44,0x00,0x00};
    static const UINT8 nop7[] = {0x0F,0x1F,0x80,0x00,0x00,0x00,0x00};
    static const UINT8 nop8[] = {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00};
    static const UINT8 nop9[] = {0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00};
    static const struct { const UINT8 *d; UINT8 n; } nops[] = {
        {nullptr,0},{nop1,1},{nop2,2},{nop3,3},{nop4,4},
        {nop5,5},{nop6,6},{nop7,7},{nop8,8},{nop9,9}
    };
    UINT32 off = 0;
    while (off < len) {
        UINT8 sz = (UINT8)((len - off) >= 9 ? 9 : (len - off));
        for (UINT8 i = 0; i < sz; i++) buf[off + i] = nops[sz].d[i];
        off += sz;
    }
}

/* ── E9 rel32 JMP encoder ───────────────────────────────────────────────── */
static void EncodeJmpRel32(UINT8 *buf, UINT64 fromVA, UINT64 toVA) {
    INT32 rel = (INT32)((INT64)toVA - (INT64)(fromVA + 5));
    buf[0] = 0xE9;
    *(INT32*)(buf + 1) = rel;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  LazyHook_Install
 * ══════════════════════════════════════════════════════════════════════════ */
extern "C" int LazyHook_Install(UINT64 cr3,
                                 UINT64 hookVA, UINT8 stolenLen,
                                 const UINT8 *shellcode, UINT32 shellcodeLen,
                                 UINT64 caveVA)
{
    { char _lb[128]; wsprintfA(_lb,
        "LH_Install: hook=0x%I64X cave=0x%I64X stolen=%u scLen=%u",
        hookVA, caveVA, stolenLen, shellcodeLen); WriteLogFile(_lb); }

    if (!cr3 || !hookVA || !caveVA || !shellcode || !shellcodeLen)
        { WriteLogFile("LH_Install: -1 bad params"); return -1; }
    if (stolenLen < 5 || stolenLen > LAZYHOOK_MAX_STOLEN)
        { WriteLogFile("LH_Install: -1 stolenLen"); return -1; }

    INT64 delta = (INT64)caveVA - (INT64)(hookVA + 5);
    if (delta > 0x7FFFFFFFLL || delta < -0x80000000LL)
        { WriteLogFile("LH_Install: -1 delta out of range"); return -1; }

    UINT32 caveNeeded = shellcodeLen + stolenLen + 5;
    if (caveNeeded > 512)
        { WriteLogFile("LH_Install: -1 caveNeeded>512"); return -1; }

    /* ── Find a free slot ──────────────────────────────────────────────────── */
    int slot = -1;
    for (int i = 0; i < s_count; i++)
        if (!s_hooks[i].installed) { slot = i; break; }
    if (slot == -1) {
        if (s_count >= LAZYHOOK_MAX)
            { WriteLogFile("LH_Install: -1 table full"); return -1; }
        slot = s_count++;
    }

    LazyHookEntry *e = &s_hooks[slot];
    memset(e, 0, sizeof(*e));
    e->hookVA    = (UINT64)SERAPH_ENC_PTR((PVOID)hookVA, &e->hookVA);
    e->caveVA    = (UINT64)SERAPH_ENC_PTR((PVOID)caveVA, &e->caveVA);
    e->stolenLen = stolenLen;
    e->caveUsed  = caveNeeded;

    /* Step 1: Save stolen bytes */
    if (!DMA_ReadVA(cr3, hookVA, e->originalBytes, stolenLen))
        { WriteLogFile("LH_Install: -1 step1 read failed"); return -1; }

    /* Step 2: Build cave payload = [ shellcode | stolen | JMP-back ] */
    UINT8  caveBuf[512];
    UINT32 pos = 0;
    memcpy(caveBuf, shellcode, shellcodeLen); pos += shellcodeLen;
    memcpy(caveBuf + pos, e->originalBytes, stolenLen); pos += stolenLen;
    EncodeJmpRel32(caveBuf + pos, caveVA + pos, hookVA + stolenLen); pos += 5;

    /* Step 3: Write cave payload */
    if (!DMA_WriteVAPhys(caveVA, caveBuf, pos))
        { WriteLogFile("LH_Install: -1 step3 cave write failed"); return -1; }
    WriteLogFile("LH_Install: step3 cave write OK");

    /* Step 4: Write hook JMP + NOP padding */
    UINT8 hookPatch[LAZYHOOK_MAX_STOLEN];
    EncodeJmpRel32(hookPatch, hookVA, caveVA);
    if (stolenLen > 5) FillMultiByteNop(hookPatch + 5, stolenLen - 5);
    if (!DMA_WriteVAPhys(hookVA, hookPatch, stolenLen)) {
        WriteLogFile("LH_Install: -1 step4 hook write failed");
        UINT8 brk[512]; memset(brk, 0xCC, pos);
        DMA_WriteVAPhys(caveVA, brk, pos);
        return -1;
    }
    DMA_RestorePageReadOnly(hookVA);
    WriteLogFile("LH_Install: step4 hook write OK");

    e->installed = TRUE;
    return slot;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  LazyHook_Remove
 * ══════════════════════════════════════════════════════════════════════════ */
extern "C" BOOL LazyHook_Remove(int id, UINT64 cr3) {
    if (id < 0 || id >= s_count) return FALSE;
    LazyHookEntry *e = &s_hooks[id];
    if (!e->installed) return TRUE;
    if (!cr3) return FALSE;

    UINT64 hookVA = (UINT64)SERAPH_DEC_PTR(e->hookVA, &e->hookVA);
    UINT64 caveVA = (UINT64)SERAPH_DEC_PTR(e->caveVA, &e->caveVA);

    if (!DMA_WriteVAPhys(hookVA, e->originalBytes, e->stolenLen)) return FALSE;
    DMA_RestorePageReadOnly(hookVA);

    UINT8 brk[512]; memset(brk, 0xCC, e->caveUsed);
    DMA_WriteVAPhys(caveVA, brk, e->caveUsed);

    memset(e, 0, sizeof(*e));
    return TRUE;
}

extern "C" void LazyHook_RemoveAll(UINT64 cr3) {
    for (int i = 0; i < s_count; i++)
        if (s_hooks[i].installed) LazyHook_Remove(i, cr3);
    s_count = 0;
}

extern "C" const LazyHookEntry *LazyHook_Get(int id) {
    if (id < 0 || id >= s_count) return nullptr;
    static LazyHookEntry dec_entry;
    dec_entry = s_hooks[id];
    dec_entry.hookVA = (UINT64)SERAPH_DEC_PTR(s_hooks[id].hookVA, &s_hooks[id].hookVA);
    dec_entry.caveVA = (UINT64)SERAPH_DEC_PTR(s_hooks[id].caveVA, &s_hooks[id].caveVA);
    return &dec_entry;
}

extern "C" void LazyHook_ResetLocalState(void) {
    memset(s_hooks, 0, sizeof(s_hooks));
    s_count = 0;
}

extern "C" int LazyHook_Count(void) { return s_count; }
