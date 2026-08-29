
#include "patch.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "debug.h"
#include "ThemidaSDK.h"
#include <string.h>

#define MAX_PATCHES 64

static PatchEntry s_patches[MAX_PATCHES];
static int        s_count = 0;

int Patch_Register(const char *name, UINT64 va, const UINT8 *patchBytes, UINT8 len) {
    if (!name || !patchBytes || len == 0 || len > PATCH_MAX_BYTES) return -1;
    if (s_count >= MAX_PATCHES) return -1;

    PatchEntry *e = &s_patches[s_count];
    memset(e, 0, sizeof(*e));
    e->va      = va;
    e->len     = len;
    e->applied = FALSE;
    strncpy(e->name, name, sizeof(e->name) - 1);
    for (UINT32 _i = 0; _i < len; _i++) e->patched[_i] = patchBytes[_i];

    /* Read original bytes NOW so same-VA patches (e.g. Godmode/Ghostmode)
     * always have valid originals regardless of apply order. */
    UINT64 cr3 = GetDestiny2CR3();
    if (cr3) {
        BYOVD_LOCK();
        if (BYOVD_ReadVA(cr3, va, e->original, len)) {
            e->originalLoaded = TRUE;
            DEBUG_PATCH("  original bytes pre-read OK");
            DEBUG_PATCH_HEX("  original", e->original, len);
        } else {
            DEBUG_PATCH("  WARNING: original pre-read FAILED (will retry at Apply)");
        }
        BYOVD_UNLOCK();
    }

    DEBUG_PATCH("=== Patch_Register[%d]: name='%s' va=0x%I64X len=%u ===", s_count, name, va, len);
    DEBUG_PATCH_HEX("  patchBytes", patchBytes, len);
    return s_count++;
}

__declspec(noinline)
#pragma optimize("", off)
BOOL Patch_Apply(int id) {
    /* MUTATE: byte-level patch primitive — every cheat feature uses this.
     * Mutating obscures the BYOVD_WriteVA orchestration and verification.
     * noinline: Patch_Toggle/Patch_RestoreAll loops call this; without noinline
     * LTCG inlines multiple MUTATE pairs side by side -> Themida "Nested". */
    MUTATE_START
    BOOL _pa_result = FALSE;
    if (id < 0 || id >= s_count) goto _pa_end;
    PatchEntry *e = &s_patches[id];
    if (e->applied) { _pa_result = TRUE; goto _pa_end; }

    UINT64 cr3 = GetDestiny2CR3();
    DEBUG_PATCH("=== Patch_Apply[%d]: '%s' va=0x%I64X len=%u ===", id, e->name, e->va, e->len);
    if (!cr3) {
        DEBUG_PATCH("  FAIL: no CR3 (attach first)");
        goto _pa_end;
    }
    DEBUG_PATCH("  cr3=0x%I64X", cr3);

    /* Only read originals if not already pre-loaded at Register time.
     * Pre-read guarantees correct originals for same-VA patches (e.g. Godmode/Ghostmode). */
    BYOVD_LOCK();
    if (!e->originalLoaded) {
        if (!BYOVD_ReadVA(cr3, e->va, e->original, e->len)) {
            DEBUG_PATCH("  FAIL: BYOVD_ReadVA original at 0x%I64X", e->va);
            BYOVD_UNLOCK();
            goto _pa_end;
        }
        e->originalLoaded = TRUE;
    }
    DEBUG_PATCH_HEX("  original", e->original, e->len);
    DEBUG_PATCH_HEX("  patched ", e->patched,  e->len);

    if (!BYOVD_WriteVA_Fresh(cr3, e->va, e->patched, e->len)) {
        DEBUG_PATCH("  FAIL: BYOVD_WriteVA_Fresh at 0x%I64X", e->va);
        BYOVD_UNLOCK();
        goto _pa_end;
    }

    /* Verify write */
    UINT8 vbuf[PATCH_MAX_BYTES];
    BOOL verifyOk = FALSE;
    if (BYOVD_ReadVA(cr3, e->va, vbuf, e->len)) {
        if (memcmp(vbuf, e->patched, e->len) == 0) {
            DEBUG_PATCH("  Verify: MATCH");
            verifyOk = TRUE;
        } else {
            DEBUG_PATCH("  Verify: MISMATCH!");
            DEBUG_PATCH_HEX("  Expected", e->patched, e->len);
            DEBUG_PATCH_HEX("  Got     ", vbuf,       e->len);
        }
    } else {
        DEBUG_PATCH("  Verify: read-back failed");
    }
    if (verifyOk) {
        e->applied = TRUE;
        BYOVD_UNLOCK();
        DEBUG_PATCH("  Apply OK");
        _pa_result = TRUE;
    } else {
        /* Write succeeded but verify failed or read-back failed —
         * the page may be write-protected or the VA is invalid.
         * DO NOT set applied=TRUE, so the next attempt retries. */
        DEBUG_PATCH("  Apply FAILED (verify) — applied NOT set");
        BYOVD_UNLOCK();
    }
_pa_end:
    MUTATE_END
    return _pa_result;
}
#pragma optimize("", on)

__declspec(noinline)
#pragma optimize("", off)
BOOL Patch_Restore(int id) {
    /* MUTATE: restore path mirrors apply — same protection rationale.
     * noinline: Patch_Reset/Patch_Toggle/Attach_Invalidate cascade calls
     * this in a loop; inlining causes Themida "Nested" marker errors. */
    MUTATE_START
    BOOL _pr_result = FALSE;
    if (id < 0 || id >= s_count) goto _pr_end;
    PatchEntry *e = &s_patches[id];
    if (!e->applied) { _pr_result = TRUE; goto _pr_end; }

    UINT64 cr3 = GetDestiny2CR3();
    DEBUG_PATCH("=== Patch_Restore[%d]: '%s' va=0x%I64X len=%u ===", id, e->name, e->va, e->len);
    if (!cr3) {
        DEBUG_PATCH("  FAIL: no CR3");
        goto _pr_end;
    }
    DEBUG_PATCH_HEX("  restoring", e->original, e->len);

    BYOVD_LOCK();
    if (!BYOVD_WriteVA_Fresh(cr3, e->va, e->original, e->len)) {
        DEBUG_PATCH("  FAIL: BYOVD_WriteVA_Fresh at 0x%I64X", e->va);
        BYOVD_UNLOCK();
        goto _pr_end;
    }

    /* Verify restore */
    UINT8 vbuf[PATCH_MAX_BYTES];
    if (BYOVD_ReadVA(cr3, e->va, vbuf, e->len)) {
        if (memcmp(vbuf, e->original, e->len) == 0)
            DEBUG_PATCH("  Restore verify: MATCH");
        else {
            DEBUG_PATCH("  Restore verify: MISMATCH!");
            DEBUG_PATCH_HEX("  Expected", e->original, e->len);
            DEBUG_PATCH_HEX("  Got     ", vbuf,        e->len);
        }
    }
    e->applied = FALSE;
    BYOVD_UNLOCK();

    DEBUG_PATCH("  Restore OK");
    _pr_result = TRUE;
_pr_end:
    MUTATE_END
    return _pr_result;
}
#pragma optimize("", on)

BOOL Patch_Toggle(int id) {
    if (id < 0 || id >= s_count) return FALSE;
    if (s_patches[id].applied)
        return Patch_Restore(id) ? FALSE : s_patches[id].applied;
    else
        return Patch_Apply(id)   ? TRUE  : s_patches[id].applied;
}

BOOL Patch_IsApplied(int id) {
    if (id < 0 || id >= s_count) return FALSE;
    return s_patches[id].applied;
}

const char *Patch_GetName(int id) {
    if (id < 0 || id >= s_count) return NULL;
    return s_patches[id].name;
}

int Patch_Count(void) {
    return s_count;
}

void Patch_Reset(void) {
    /* C-6: Restore any applied patches before clearing — BYOVD_LOCK protects each write
     * against the render thread that may be calling Tick() concurrently. */
    for (int i = 0; i < s_count; i++) {
        if (s_patches[i].applied) {
            UINT64 cr3 = GetDestiny2CR3();
            if (cr3) {
                BYOVD_LOCK();
                BYOVD_WriteVA_Fresh(cr3, s_patches[i].va, s_patches[i].original, s_patches[i].len);
                BYOVD_UNLOCK();
            }
            s_patches[i].applied = FALSE;
        }
    }
    memset(s_patches, 0, sizeof(s_patches));
    s_count = 0;
    DEBUG_PATCH("Patch_Reset: cleared all patch entries");
}

void Patch_RestoreAll(void) {
    DEBUG_PATCH("Patch_RestoreAll: restoring %d patches", s_count);
    for (int i = 0; i < s_count; i++) {
        if (s_patches[i].applied) {
            DEBUG_PATCH("  Restoring patch[%d]='%s'", i, s_patches[i].name);
            Patch_Restore(i);
        }
    }
    DEBUG_PATCH("Patch_RestoreAll done");
}

/* ── Periodic re-verify + re-apply ───────────────────────────────────────
 * C-10: The game engine's JIT or anti-tamper can silently overwrite our
 * patches.  Patch_Tick scans applied patches once per second and re-applies
 * any whose bytes no longer match the expected patched[] sequence.  This is
 * the root cause of Godmode/Ghostmode randomly deactivating — the write
 * succeeded at Patch_Apply time but was later undone by the game. */
void Patch_Tick(void) {
    static DWORD s_lastTick = 0;
    DWORD now = GetTickCount();
    if (now - s_lastTick < 1000) return;  /* once per second — cheap */
    s_lastTick = now;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    for (int i = 0; i < s_count; i++) {
        if (!s_patches[i].applied) continue;
        if (!s_patches[i].len || s_patches[i].len > PATCH_MAX_BYTES) continue;

        UINT8 cur[PATCH_MAX_BYTES];
        BOOL ok = FALSE;
        if (BYOVD_TRYLOCK()) {
            if (BYOVD_ReadVA(cr3, s_patches[i].va, cur, s_patches[i].len)) {
                if (memcmp(cur, s_patches[i].patched, s_patches[i].len) != 0) {
                    DEBUG_PATCH("Patch_Tick: '%s' overwritten — re-applying",
                                s_patches[i].name);
                    BYOVD_WriteVA_Fresh(cr3, s_patches[i].va,
                                        s_patches[i].patched, s_patches[i].len);
                }
            }
            BYOVD_UNLOCK();
        }
        (void)ok;
    }
}

void Patch_SetBytes(int id, const UINT8 *bytes, UINT8 len) {
    if (id < 0 || id >= s_count || !bytes || len == 0 || len > PATCH_MAX_BYTES) {
        DEBUG_PATCH("Patch_SetBytes[%d]: invalid args (len=%u)", id, len);
        return;
    }
    DEBUG_PATCH("Patch_SetBytes[%d]: '%s' new len=%u", id, s_patches[id].name, len);
    DEBUG_PATCH_HEX("  newBytes", bytes, len);
    s_patches[id].len = len;
    for (UINT32 _i = 0; _i < len; _i++) s_patches[id].patched[_i] = bytes[_i];
}

PatchEntry *Patch_GetEntry(int id) {
    if (id < 0 || id >= s_count) return NULL;
    return &s_patches[id];
}

