
#include "lazyhook.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "debug.h"
#include "ThemidaSDK.h"
#include "cave_finder.h"
#include "seraph_ptr_crypt.h"
#include <string.h>

static LazyHookEntry s_hooks[LAZYHOOK_MAX];
static int           s_count = 0;

/* ── Multi-byte NOP generator ───────────────────────────────────────────── */
static void FillMultiByteNop(UINT8 *buf, UINT32 len)
{
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
        {NULL,0},{nop1,1},{nop2,2},{nop3,3},{nop4,4},
        {nop5,5},{nop6,6},{nop7,7},{nop8,8},{nop9,9}
    };
    UINT32 off = 0;
    while (off < len) {
        UINT8 sz = (UINT8)((len - off) >= 9 ? 9 : (len - off));
        const UINT8 *src = nops[sz].d;
        for (UINT8 i = 0; i < sz; i++) buf[off + i] = src[i];
        off += sz;
    }
}

/* ── Encode a 5-byte E9 relative JMP ───────────────────────────────────── */
static void EncodeJmpRel32(UINT8 *buf, UINT64 fromVA, UINT64 toVA)
{
    INT32 rel = (INT32)((INT64)toVA - (INT64)(fromVA + 5));
    buf[0] = 0xE9;
    *(INT32*)(buf + 1) = rel;
    DEBUG_HOOK("  EncodeJmpRel32: from=0x%I64X to=0x%I64X rel=0x%08X bytes=[E9 %02X %02X %02X %02X]",
               fromVA, toVA, (UINT32)rel,
               buf[1], buf[2], buf[3], buf[4]);
}

/* ── Public API ─────────────────────────────────────────────────────────── */

__declspec(noinline)
#pragma optimize("", off)
int LazyHook_Install(UINT64 cr3,
                     UINT64 hookVA, UINT8 stolenLen,
                     const UINT8 *shellcode, UINT32 shellcodeLen,
                     UINT64 caveVA)
{
    /* MUTATE: hook installer is called on every feature toggle ON.
     * noinline: prevents LTCG cascade inlining into feature SetEnabled
     * paths which would create nested MUTATE markers. */
    MUTATE_START
    int _lhi_result = -1;
    DEBUG_HOOK("=== LazyHook_Install START ===");
    DEBUG_HOOK("  cr3=0x%I64X hookVA=0x%I64X caveVA=0x%I64X", cr3, hookVA, caveVA);
    DEBUG_HOOK("  stolenLen=%u shellcodeLen=%u", stolenLen, shellcodeLen);
    /* ── Find a free slot ───────────────────────────────────────────────── */
    int slot = -1;
    for (int i = 0; i < s_count; i++) {
        if (!s_hooks[i].installed) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        if (s_count >= LAZYHOOK_MAX) {
            DEBUG_HOOK("  FAIL: max hooks reached (%d) and no free slots", LAZYHOOK_MAX);
            goto _lhi_end;
        }
        slot = s_count++;
    }

    DEBUG_HOOK("  slot=%d / %d", slot, LAZYHOOK_MAX);
    if (stolenLen < 5 || stolenLen > LAZYHOOK_MAX_STOLEN) {
        DEBUG_HOOK("  FAIL: stolenLen=%u invalid (need 5..%d)", stolenLen, LAZYHOOK_MAX_STOLEN);
        goto _lhi_end;
    }
    if (!shellcode || !shellcodeLen) {
        DEBUG_HOOK("  FAIL: shellcode=NULL or empty");
        goto _lhi_end;
    }
    if (!hookVA || !caveVA || !cr3) {
        DEBUG_HOOK("  FAIL: null hookVA/caveVA/cr3");
        goto _lhi_end;
    }

    UINT32 caveNeeded = shellcodeLen + stolenLen + 5;
    INT64  delta      = (INT64)caveVA - (INT64)(hookVA + 5);
    DEBUG_HOOK("  caveNeeded=%u (shellcode=%u + stolen=%u + jmpback=5)",
               caveNeeded, shellcodeLen, stolenLen);
    DEBUG_HOOK("  hook->cave delta=0x%I64X (must fit in INT32: %s)",
               (UINT64)delta,
               (delta >= -0x80000000LL && delta <= 0x7FFFFFFFLL) ? "OK" : "TOO FAR");

    if (delta > 0x7FFFFFFFLL || delta < -0x80000000LL) {
        DEBUG_HOOK("  FAIL: cave too far from hook for E9 rel32");
        goto _lhi_end;
    }

    if (caveNeeded > 512) {
        DEBUG_HOOK("  FAIL: cave payload too large (%u > 512)", caveNeeded);
        goto _lhi_end;
    }

    /* P4: Validar tamanho real reservado da cave contra a necessidade do hook
     * para evitar corrupção de instruções adjacentes na seção .text do jogo. */
    UINT32 reservedSize = CaveFinder_GetReservedSize(caveVA);
    if (reservedSize > 0 && caveNeeded > reservedSize) {
        DEBUG_HOOK("  FAIL: cave at 0x%I64X is too small (%u reserved, but need %u)",
                   caveVA, reservedSize, caveNeeded);
        goto _lhi_end;
    }


    LazyHookEntry *e = &s_hooks[slot];
    memset(e, 0, sizeof(*e));
    e->hookVA    = (UINT64)SERAPH_ENC_PTR((PVOID)hookVA, &e->hookVA);
    e->caveVA    = (UINT64)SERAPH_ENC_PTR((PVOID)caveVA, &e->caveVA);
    e->stolenLen = stolenLen;
    e->caveUsed  = caveNeeded;

    /* ── Step 1: Read original bytes at hookVA ──────────────────────────── */
    DEBUG_HOOK("--- Step 1: Read original bytes at hookVA=0x%I64X len=%u ---", hookVA, stolenLen);
    BYOVD_LOCK();
    if (!BYOVD_ReadVA(cr3, hookVA, e->originalBytes, stolenLen)) {
        BYOVD_UNLOCK();
        DEBUG_HOOK("  FAIL: BYOVD_ReadVA returned FALSE");
        goto _lhi_end;
    }
    BYOVD_UNLOCK();
    DEBUG_HOOK_HEX("  originalBytes", e->originalBytes, stolenLen);

    /* ── Step 2: Build cave payload ─────────────────────────────────────── */
    DEBUG_HOOK("--- Step 2: Build cave payload ---");
    UINT8  caveBuf[512];
    UINT32 pos = 0;

    /* 2a. User shellcode at cave+0 */
    DEBUG_HOOK("  [cave+0x%X] shellcode (%u bytes)", pos, shellcodeLen);
    DEBUG_HOOK_HEX("  shellcode", shellcode, shellcodeLen);
    for (UINT32 i = 0; i < shellcodeLen; i++) caveBuf[pos + i] = shellcode[i];
    pos += shellcodeLen;

    /* 2b. Stolen original instructions at cave+shellcodeLen */
    DEBUG_HOOK("  [cave+0x%X] stolen instructions (%u bytes)", pos, stolenLen);
    for (UINT8 i = 0; i < stolenLen; i++) caveBuf[pos + i] = e->originalBytes[i];
    pos += stolenLen;

    /* 2c. JMP back to hookVA+stolenLen */
    UINT64 returnVA  = hookVA + stolenLen;
    UINT64 jmpFromVA = caveVA + pos;
    DEBUG_HOOK("  [cave+0x%X] JMP back: from=0x%I64X to=0x%I64X (returnVA)",
               pos, jmpFromVA, returnVA);
    EncodeJmpRel32(caveBuf + pos, jmpFromVA, returnVA);
    pos += 5;

    DEBUG_HOOK("  Cave payload total: %u bytes", pos);
    DEBUG_HOOK_HEX("  Full cave payload", caveBuf, pos);

    /* Cave layout summary */
    DEBUG_HOOK("  Cave layout summary:");
    DEBUG_HOOK("    0x%I64X : shellcode        (%u bytes)", caveVA, shellcodeLen);
    DEBUG_HOOK("    0x%I64X : stolen instrs    (%u bytes)", caveVA + shellcodeLen, stolenLen);
    DEBUG_HOOK("    0x%I64X : JMP back -> 0x%I64X (5 bytes)",
               caveVA + shellcodeLen + stolenLen, returnVA);

    /* ── Step 3: Write cave via physical BYOVD engine ──────────────────────────── */
    DEBUG_HOOK("--- Step 3: Write cave at 0x%I64X (%u bytes) ---", caveVA, pos);
    BYOVD_LOCK();
    if (!BYOVD_WriteVA_Fresh(cr3, caveVA, caveBuf, pos)) {
        BYOVD_UNLOCK();
        DEBUG_HOOK("  FAIL: BYOVD_WriteVA_Fresh(cave) returned FALSE");
        goto _lhi_end;
    }
    DEBUG_HOOK("  Cave write OK");
    BYOVD_UNLOCK();

    /* ── Step 4: Write JMP + NOPs at hook point ──────────────────────────── */
    DEBUG_HOOK("--- Step 4: Write hook patch at 0x%I64X (%u bytes) ---", hookVA, stolenLen);
    UINT8 hookPatch[LAZYHOOK_MAX_STOLEN];
    EncodeJmpRel32(hookPatch, hookVA, caveVA);
    if (stolenLen > 5) {
        FillMultiByteNop(hookPatch + 5, stolenLen - 5);
        DEBUG_HOOK("  NOP padding %u bytes at hook+5", stolenLen - 5);
        DEBUG_HOOK_HEX("  NOP padding", hookPatch + 5, stolenLen - 5);
    }
    DEBUG_HOOK_HEX("  Full hook patch", hookPatch, stolenLen);

    BYOVD_LOCK();
    if (!BYOVD_WriteVA_Fresh(cr3, hookVA, hookPatch, stolenLen)) {
        /* Roll back cave with NOPs via physical write */
        UINT8 ccFill[512];
        FillMultiByteNop(ccFill, pos);
        BOOL rbOk = BYOVD_WriteVA_Fresh(cr3, caveVA, ccFill, pos);
        BYOVD_UNLOCK();
        DEBUG_HOOK("  FAIL: BYOVD_WriteVA_Fresh(hook) returned FALSE — cave rollback: %s", rbOk ? "OK" : "FAIL");
        goto _lhi_end;
    }
    DEBUG_HOOK("  Hook patch write OK");

    /* Verify hook patch */
    UINT8 hverify[LAZYHOOK_MAX_STOLEN];
    if (BYOVD_ReadVA(cr3, hookVA, hverify, stolenLen)) {
        if (memcmp(hverify, hookPatch, stolenLen) == 0) {
            DEBUG_HOOK("  Hook verify: MATCH");
        } else {
            DEBUG_HOOK("  Hook verify: MISMATCH!");
            DEBUG_HOOK_HEX("  Expected", hookPatch, stolenLen);
            DEBUG_HOOK_HEX("  Got     ", hverify,   stolenLen);
        }
    }
    BYOVD_UNLOCK();

    e->installed = TRUE;
    DEBUG_HOOK("=== LazyHook_Install SUCCESS: id=%d ===", slot);
    DEBUG_HOOK("  hookVA=0x%I64X -> caveVA=0x%I64X stolen=%u shellcode=%u total_cave=%u",
               hookVA, caveVA, stolenLen, shellcodeLen, pos);
    _lhi_result = slot;
_lhi_end:
    MUTATE_END
    return _lhi_result;
}
#pragma optimize("", on)

__declspec(noinline)
#pragma optimize("", off)
BOOL LazyHook_Remove(int hookId, UINT64 cr3)
{
    /* MUTATE: hook removal restores stolen bytes and fills cave with 0xCC.
     * noinline: LazyHook_RemoveAll loops over this — inlining would emit
     * N MUTATE pairs side by side, triggering Themida "Nested". */
    MUTATE_START
    BOOL _lhr_result = FALSE;
    DEBUG_HOOK("=== LazyHook_Remove: id=%d cr3=0x%I64X ===", hookId, cr3);

    if (hookId < 0 || hookId >= s_count) {
        DEBUG_HOOK("  FAIL: invalid hookId=%d (count=%d)", hookId, s_count);
        goto _lhr_end;
    }
    LazyHookEntry *e = &s_hooks[hookId];
    if (!e->installed) {
        DEBUG_HOOK("  Already removed (installed=FALSE), no-op");
        _lhr_result = TRUE;
        goto _lhr_end;
    }

    UINT64 hookVA = (UINT64)SERAPH_DEC_PTR(e->hookVA, &e->hookVA);
    UINT64 caveVA = (UINT64)SERAPH_DEC_PTR(e->caveVA, &e->caveVA);

    DEBUG_HOOK("  hookVA=0x%I64X caveVA=0x%I64X stolenLen=%u caveUsed=%u",
               hookVA, caveVA, e->stolenLen, e->caveUsed);
    DEBUG_HOOK_HEX("  Restoring original bytes", e->originalBytes, e->stolenLen);

    /* Restore original bytes */
    BYOVD_LOCK();
    if (!BYOVD_WriteVA_Fresh(cr3, hookVA, e->originalBytes, e->stolenLen)) {
        BYOVD_UNLOCK();
        DEBUG_HOOK("  FAIL: BYOVD_WriteVA_Fresh(restore) failed at 0x%I64X", hookVA);
        goto _lhr_end;
    }
    DEBUG_HOOK("  Original bytes restored OK");

    /* Verify restore */
    UINT8 rv[LAZYHOOK_MAX_STOLEN];
    if (BYOVD_ReadVA(cr3, hookVA, rv, e->stolenLen)) {
        if (memcmp(rv, e->originalBytes, e->stolenLen) == 0) {
            DEBUG_HOOK("  Restore verify: MATCH");
        } else {
            DEBUG_HOOK("  Restore verify: MISMATCH!");
            DEBUG_HOOK_HEX("  Expected", e->originalBytes, e->stolenLen);
            DEBUG_HOOK_HEX("  Got     ", rv,               e->stolenLen);
        }
    }

    /* Fill cave with 0xCC (file-backed padding pattern).  Safe because the
     * JMP at hookVA was already restored above, so no new thread can enter
     * the cave; any in-flight execution is already past us.  Critically,
     * CaveFinder recognizes runs of repeating bytes (CC or 00) as caves,
     * so this restores reusability for subsequent re-installs.            */
    if (e->caveUsed > 0 && e->caveUsed <= 512) {
        UINT8 ccFill[512];
        memset(ccFill, 0xCC, e->caveUsed);
        BOOL wOk = BYOVD_WriteVA_Fresh(cr3, caveVA, ccFill, e->caveUsed);
        DEBUG_HOOK("  Cave fill 0xCC (%u bytes at 0x%I64X): %s",
                   e->caveUsed, caveVA, wOk ? "OK" : "FAIL");
    }
    BYOVD_UNLOCK();

    e->installed = FALSE;
    DEBUG_HOOK("=== LazyHook_Remove[%d] DONE ===", hookId);
    _lhr_result = TRUE;
_lhr_end:
    MUTATE_END
    return _lhr_result;
}
#pragma optimize("", on)

void LazyHook_RemoveAll(UINT64 cr3)
{
    DEBUG_HOOK("LazyHook_RemoveAll: removing %d hooks", s_count);
    for (int i = 0; i < s_count; i++) {
        if (s_hooks[i].installed) {
            UINT64 hookVA = (UINT64)SERAPH_DEC_PTR(s_hooks[i].hookVA, &s_hooks[i].hookVA);
            DEBUG_HOOK("  Removing hook[%d] at hookVA=0x%I64X", i, hookVA);
            LazyHook_Remove(i, cr3);
        } else {
            DEBUG_HOOK("  Hook[%d]: already removed, skip", i);
        }
    }
    DEBUG_HOOK("LazyHook_RemoveAll: done");
}

const LazyHookEntry *LazyHook_Get(int hookId)
{
    if (hookId < 0 || hookId >= s_count) {
        DEBUG_HOOK("LazyHook_Get: invalid id=%d", hookId);
        return NULL;
    }
    static LazyHookEntry dec_entry;
    dec_entry = s_hooks[hookId];
    dec_entry.hookVA = (UINT64)SERAPH_DEC_PTR(s_hooks[hookId].hookVA, &s_hooks[hookId].hookVA);
    dec_entry.caveVA = (UINT64)SERAPH_DEC_PTR(s_hooks[hookId].caveVA, &s_hooks[hookId].caveVA);
    DEBUG_HOOK("LazyHook_Get[%d]: hookVA=0x%I64X installed=%d", hookId, dec_entry.hookVA, dec_entry.installed);
    return &dec_entry;
}

int LazyHook_Count(void)
{
    int n = 0;
    for (int i = 0; i < s_count; i++) if (s_hooks[i].installed) n++;
    DEBUG_HOOK("LazyHook_Count: %d installed / %d registered", n, s_count);
    return n;
}

void LazyHook_ResetLocalState(void)
{
    memset(s_hooks, 0, sizeof(s_hooks));
    s_count = 0;
    DEBUG_HOOK("LazyHook_ResetLocalState: cleared hook table");
}

