
#include "ThemidaSDK.h"
#include "xor_strings.h"
#include "d2_patches.h"
#include "patch.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "debug.h"
#include <string.h>
#include <windows.h>
#include "aob_cache.h"
#include "aob_patterns.h"

/* ── Scan-based patch entry ─────────────────────────────────────────────────
 * Locates the instruction at runtime via byte signature scan.
 * pattern/mask: 0xFF = exact, 0x00 = wildcard.
 * patch_offset: byte offset from scan match start to write patch_bytes.
 * scan_size:    how many bytes to scan from imageBase (0 = disabled).
 * tab:          1=MISC, 2=SETTING, 3=DEV
 * ─────────────────────────────────────────────────────────────────────────*/
typedef struct {
    const char  *name;
    UINT64       scan_size;
    const UINT8 *pattern;
    const UINT8 *mask;
    UINT8        sig_len;
    UINT8        patch_offset; /* offset from match VA to apply patch_bytes */
    UINT8        patch_bytes[16];
    UINT8        patch_len;
    int          tab;          /* 1=MISC, 3=DEV, 4=PLAYER */
    int          mutex_group;  /* 0=independent, >0=mutually exclusive with same group */
    UINT8        original_bytes[16]; /* known original bytes at patch_offset (for crash recovery) */
    UINT8        original_len;       /* 0 = unknown/not needed */
} D2ScanPatch;




static const D2ScanPatch k_patches[] = {
    {
        "Infinite Stacks",
        0x20000000ULL,  /* 512MB */
        k_istk_pat, k_istk_mask, 7,
        0,
        {0xC6,0x47,0x30,0x63,0x0F,0x1F,0x00}, 7,
        1,  /* MISC tab */
        0,  /* independent */
        {0x83,0x7F,0x2C,0xFF,0x89,0x5F,0x30}, 7 /* original */
    },
    {
        "Sparrow Anywhere",
        0x20000000ULL,
        k_spw_pat, k_spw_mask, 9,
        0x6D, /* byte at match+0x6D: je→jne (confirmed by user) */
        {0x75}, 1,
        5,  /* MOVEMENT tab */
        0   /* independent */
    },
    {
        "Shoot Through Walls",
        0x20000000ULL,  /* 512MB */
        k_stw_pat, k_stw_mask, 16,
        0,
        /* NOP apenas os 7 bytes das duas instrucoes movups:
         *   0F 11 02        movups [rdx], xmm0    (3 bytes)
         *   0F 11 4A 10     movups [rdx+10h], xmm1 (4 bytes)
         * 7-byte NOP: nop dword ptr [rax+00000000h]                          */
        {0x0F,0x1F,0x80,0x00,0x00,0x00,0x00}, 7,
        6,  /* WEAPONS tab */
        0,  /* independent */
        {0x0F,0x11,0x02,0x0F,0x11,0x4A,0x10}, 7 /* original */
    },
    {
        "Infinite Timers",
        0x20000000ULL,  /* 512MB */
        k_itim_pat, k_itim_mask, 10,
        0,
        {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00, 0x66,0x90}, 10,
        1,  /* MISC tab */
        2,  /* mutex group 2: exclusive with No Timers */
        {0x48,0x2B,0xC8,0x48,0x89,0x8B,0xA0,0x00,0x00,0x00}, 10 /* original */
    },
    {
        "No Timers",
        0x20000000ULL,  /* 512MB */
        k_itim_pat, k_itim_mask, 10,
        0,
        {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00, 0x66,0x90}, 10,
        1,  /* MISC tab */
        2,  /* mutex group 2: exclusive with Infinite Timers */
        {0x48,0x2B,0xC8,0x48,0x89,0x8B,0xA0,0x00,0x00,0x00}, 10 /* original */
    },




    {
        "Infinite Dash",
        0x2000000ULL,  /* 32MB - crucial for this 6-byte pattern to not hit false positives */
        k_idash_pat, k_idash_mask, 6,
        0,
        /* NOP only first 3 bytes (dash charge counter write [rsi+34h]).
         * The second write [rsi+3Ch] controls physics/velocity and must be preserved.
         * 3-byte NOP: 0F 1F 00 (Intel-recommended, avoids 0x90 signature). */
        {0x0F,0x1F,0x00,0x89,0x6E,0x3C}, 6,
        5,  /* MOVEMENT tab */
        0,  /* independent */
        {0x89,0x46,0x34,0x89,0x6E,0x3C}, 6 /* original */
    },
    {
        "Godmode",
        0x20000000ULL,  /* 512MB */
        k_gmode_pat, k_gmode_mask, 11,
        0,
        /* imul ebx, ebx, 1  ->  damage * 1 (blocks normal XOR/ROL encryption path) */
        {0x6B,0xDB,0x01,0x66,0x90}, 5,
        11,  /* HEALTH tab */
        1,  /* mutex group 1: exclusive with Ghostmode */
        {0x33,0xDA,0xC1,0xC3,0x10}, 5   /* original: xor ebx,edx + rol ebx,16 */
    },
    {
        "Ghostmode",
        0x20000000ULL,  /* 512MB */
        k_gmode_pat, k_gmode_mask, 11,
        0,
        /* imul ebx, ebx, 0  ->  damage * 0 = 0  (take no damage) */
        {0x6B,0xDB,0x00,0x66,0x90}, 5,
        11,  /* HEALTH tab */
        1,  /* mutex group 1: exclusive with Godmode */
        {0x33,0xDA,0xC1,0xC3,0x10}, 5   /* original: xor ebx,edx + rol ebx,16 */
    },
    {
        /* Infinite Tokens
         * Skips call that consumes a token by flipping jne -> jmp.
         * AOB: 83 7B 18 FF 75 ?? E8 ?? ?? ?? ?? 89 43 18  (12 bytes)
         * patch_offset=4 lands on the 0x75 (jne opcode).      */
        "Infinite Tokens",
        0x20000000ULL,  /* 512MB */
        k_itok_pat, k_itok_mask, 12,
        4,
        {0xEB}, 1,                    /* jne -> jmp (unconditional) */
        4,  /* GENERAL tab */
        0,  /* independent */
        {0x75}, 1                     /* original: 0x75 (jne) */
    },
    {
        /* Infinite Sword Ammo (hidden from menu tab=0, coupled with Infinite Ammo) */
        "Infinite Sword Ammo",
        0x20000000ULL,
        k_swa_pat, k_swa_mask, 11,
        3,
        {0x0F,0x1F,0x40,0x00,0x66,0x90}, 6,
        0,  /* tab 0: hidden from menu, coupled with Infinite Ammo */
        0,  /* independent */
        {0xF3,0x0F,0x11,0x7C,0x24,0x78}, 6 /* original */
    },
    {
        "Shotgun Spread",
        0x20000000ULL,
        k_sgs_pat, k_sgs_mask, 14,
        0,
        {0x28,0xD1}, 2,
        6,  /* WEAPONS tab */
        0,  /* independent */
        {0x28,0xD3}, 2 /* original */
    },
    {
        "Instant Fusion Charge",
        0x20000000ULL,
        k_ifc_pat, k_ifc_mask, 16,
        0,
        /* and dword ptr [rdi+0x1F8], 0  →  forces charge timer to 0 (= ready)
         * Matches Vanish: C7 87 F8 01 00 00 00 00 00 00 (write 0), but fits 7 bytes.
         * Encoding: 83 /4 ModRM=A7(mod=10,AND,rdi) disp32=F8010000 imm8=00 */
        {0x83,0xA7,0xF8,0x01,0x00,0x00,0x00}, 7,
        6,  /* WEAPONS tab */
        0,  /* independent */
        {0x48,0x89,0x87,0xF8,0x01,0x00,0x00}, 7 /* original */
    },
    {
        "Instant Health Regen",
        0x20000000ULL,
        k_ihr_pat, k_ihr_mask, 9,
        0,
        {0x90,0x90,0x90,0x90,0x90,0x90,0x90}, 7,
        11,  /* HEALTH tab */
        0,  /* independent */
        {0xF3,0x41,0x0F,0x10,0x5C,0x24,0x08}, 7 /* original */
    },
    {
        "PVP Sparrow",
        0x20000000ULL,
        k_pvpspw_pat, k_pvpspw_mask, 12,
        4, /* offset 4 */
        {0xEB}, 1,
        0,  /* tab 0: hidden from menu, coupled with Sparrow Anywhere */
        0,  /* independent */
        {0x74}, 1 /* original */
    },
};


#define D2_COUNT ((int)(sizeof(k_patches)/sizeof(k_patches[0])))

/* Per-patch registered IDs (index = k_patches index) */
static int s_regIds[D2_COUNT];

/* Number of patches whose AOB scan failed in the most recent Register() pass. */
static int s_failCount = 0;
int D2Patches_GetFailCount(void) { return s_failCount; }

/* Tab and mutex_group indexed by Patch_Register id */
#define MAX_PATCH_IDS 64
static int s_tabForId[MAX_PATCH_IDS];
static int s_mutexForId[MAX_PATCH_IDS];

int D2Patches_GetTabForId(int patchId) {
    if (patchId < 0 || patchId >= MAX_PATCH_IDS) return 3;
    return s_tabForId[patchId];
}

/* External modules (HealthRegen, etc.) can register their own patch
 * in the D2 tab system by calling this after Patch_Register. */
void D2Patches_SetExternalTabForId(int patchId, int tab) {
    if (patchId >= 0 && patchId < MAX_PATCH_IDS)
        s_tabForId[patchId] = tab;
}

static UINT64 s_timerCaveMailbox = 0;

void D2Patches_TriggerNoTimersZero(void) {
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !s_timerCaveMailbox) return;
    UINT64 capturedRbx = 0;
    BYOVD_LOCK();
    if (BYOVD_ReadVA(cr3, s_timerCaveMailbox, &capturedRbx, 8) && capturedRbx > 0x10000) {
        UINT64 zeroVal = 0;
        BYOVD_WriteVA(cr3, capturedRbx + 0xA0, &zeroVal, 8);
    }
    BYOVD_UNLOCK();
}

int D2Patches_GetMutexGroup(int patchId) {
    if (patchId < 0 || patchId >= MAX_PATCH_IDS) return 0;
    return s_mutexForId[patchId];
}


#pragma optimize("", off)
void D2Patches_Register(void) {
    MUTATE_START
    /* Clear tab/mutex tables so stale entries from a previous attach don't leak */
    memset(s_tabForId,   0, sizeof(s_tabForId));
    memset(s_mutexForId, 0, sizeof(s_mutexForId));
    s_failCount = 0;
    DEBUG_PATCH("=== D2Patches_Register START (count=%d) ===", D2_COUNT);

    UINT64 base = GetDestiny2Base();
    UINT64 cr3  = GetDestiny2CR3();
    DEBUG_PATCH("  d2Base=0x%I64X cr3=0x%I64X", base, cr3);

    if (!base || !cr3) {
        DEBUG_PATCH("  FAIL: no base or cr3 — attach first");
        return;
    }

    UINT32 d2Tds = 0;
    {
        LONG e_lfanew = 0;
        BYOVD_LOCK();
        BOOL okTds = BYOVD_ReadVA(cr3, base + 0x3C, &e_lfanew, 4);
        if (okTds && e_lfanew > 0 && e_lfanew < 0x1000) {
            BYOVD_ReadVA(cr3, base + (UINT32)e_lfanew + 8, &d2Tds, 4);
        }
        BYOVD_UNLOCK();
    }

    /* ── Batch scan: one 512MB pass finds all patch patterns simultaneously ─ */
    BYOVD_SCAN_ENTRY scanEntries[D2_COUNT];

    AobCacheRec rec;
    BOOL loadedFromCache = FALSE;
#ifndef SERAPH_DMA_BUILD
    if (AobCache_Read(base, d2Tds, &rec) && rec.patches_valid) {
        loadedFromCache = TRUE;
        for (int i = 0; i < D2_COUNT; i++) {
            scanEntries[i].result = rec.patch_vas[i];
        }
        DEBUG_PATCH("  Loaded batch scan results from AOB cache");
    } else
#endif
    {
        UINT64 maxScan = 0;
        for (int i = 0; i < D2_COUNT; i++) {
            const D2ScanPatch *d = &k_patches[i];
            scanEntries[i].pattern   = d->pattern;
            scanEntries[i].mask      = d->mask;
            scanEntries[i].patLen    = d->sig_len;
            scanEntries[i].scanLimit = d->scan_size;
            scanEntries[i].result    = 0;
            if (d->scan_size > maxScan) maxScan = d->scan_size;
        }
        BYOVD_LOCK();
#ifdef SERAPH_DMA_BUILD
        {
            UINT64 imgVA = 0, imgLen = 0;
            if (!BYOVD_GetImageBounds(cr3, base, &imgVA, &imgLen)) {
                imgVA = base; imgLen = 0x20000000ULL;
            }
            BYOVD_ScanMultiPattern(cr3, imgVA, imgLen, scanEntries, D2_COUNT);
        }
#else
        BYOVD_ScanMultiPatternText(cr3, base, scanEntries, D2_COUNT);
#endif
        BYOVD_UNLOCK();
        DEBUG_PATCH("  Batch scan complete (maxScan=0x%I64X)", maxScan);

#ifndef SERAPH_DMA_BUILD
        if (AobCache_Read(base, d2Tds, &rec)) {
            for (int i = 0; i < D2_COUNT && i < 32; i++) {
                rec.patch_vas[i] = scanEntries[i].result;
            }
            rec.patches_valid = 1;
            AobCache_Write(base, d2Tds, &rec);
        }
#endif
    }


    for (int i = 0; i < D2_COUNT; i++) {
        s_regIds[i] = -1;
        const D2ScanPatch *d = &k_patches[i];

        DEBUG_PATCH("--- Patch[%d]: '%s' ---", i, d->name);
        DEBUG_PATCH("  scan_size=0x%I64X sig_len=%u patch_len=%u patch_offset=%u tab=%d",
                    d->scan_size, d->sig_len, d->patch_len, d->patch_offset, d->tab);

        if (!d->scan_size || !d->pattern || !d->mask || !d->sig_len) {
            DEBUG_PATCH("  SKIP: no scan config");
            continue;
        }

        DEBUG_PATCH_HEX("  AOB pattern", d->pattern, d->sig_len);
        DEBUG_PATCH_HEX("  AOB mask   ", d->mask,    d->sig_len);
        DEBUG_PATCH_HEX("  patch_bytes", d->patch_bytes, d->patch_len);
        DEBUG_PATCH("  Using batch result: 0x%I64X", scanEntries[i].result);

        BYOVD_LOCK();
        UINT64 va = scanEntries[i].result;
        BOOL already_patched = FALSE;
        /* Recovery scan: require >= 7 patch bytes AND a known original_bytes
         * sequence to verify context.  Common 4-byte NOPs (0F 1F 80 ...) appear
         * thousands of times in .text and would generate false-positive hits. */
        if (!va && d->original_len > 0 && d->patch_len >= 7) {
            /* Pattern not found — check if patch is still active from a crashed session.
             * Try scanning for the known patch bytes (we know them from original_bytes). */
            DEBUG_PATCH("  Original pattern not found, trying patch-bytes recovery...");
            UINT8 recover_mask[16] = {0};
            UINT8 recoverLen = d->patch_len <= 16 ? d->patch_len : 16;
            for (UINT8 mi = 0; mi < recoverLen; mi++) recover_mask[mi] = 0xFF;
            UINT64 recover_va = BYOVD_ScanPatternText(cr3, base,
                                                      d->patch_bytes, recover_mask, recoverLen);
            if (recover_va) {
                /* M-14: Check for underflow before subtraction — a false-positive
                 * match could produce recover_va < patch_offset → unsigned wrap-around. */
                if (recover_va < (UINT64)d->patch_offset) {
                    DEBUG_PATCH("  Recovery: underflow! recover_va=0x%I64X offset=%u — skip",
                                recover_va, d->patch_offset);
                } else {
                    va = recover_va - d->patch_offset;
                    already_patched = TRUE;
                    DEBUG_PATCH("  Recovery: patch still active at VA=0x%I64X, registering as applied", recover_va);
                }
            }
        }
        if (!va) {
            BYOVD_UNLOCK();
            DEBUG_PATCH("  FAIL: pattern NOT FOUND (including patched recovery)");
            { char b[160]; wsprintfA(b,"AOB MISSING (D2Patch): '%s'", d->name ? d->name : "?"); WriteLogFile(b); }
            s_failCount++;
            continue;
        }

        UINT64 patch_va = va + d->patch_offset;
        DEBUG_PATCH("  Match VA=0x%I64X patch_va=0x%I64X (offset=%u) already_patched=%d",
                    va, patch_va, d->patch_offset, already_patched);

        /* Read what's currently at patch_va for reference */
        UINT8 curBytes[16] = {0};
        UINT8 readLen = d->patch_len <= 16 ? d->patch_len : 16;
        if (BYOVD_ReadVA(cr3, patch_va, curBytes, readLen))
            DEBUG_PATCH_HEX("  Current bytes at patch_va", curBytes, readLen);
        else
            DEBUG_PATCH("  Could not read current bytes at patch_va");
        BYOVD_UNLOCK();

        int id = Patch_Register(d->name, patch_va, d->patch_bytes, d->patch_len);
        s_regIds[i] = id;
        DEBUG_PATCH("  Registered as patch id=%d", id);

        if (id >= 0 && id < MAX_PATCH_IDS) {
            s_tabForId[id]   = d->tab;
            s_mutexForId[id] = d->mutex_group;
            /* If we recovered from a crash with the patch active,
             * overwrite the original bytes with the known-good originals
             * so that Patch_Restore writes back the correct bytes. */
            if (already_patched && d->original_len > 0) {
                PatchEntry *pe = Patch_GetEntry(id);
                if (pe) {
                    for (UINT8 _i = 0; _i < d->original_len; _i++) pe->original[_i] = d->original_bytes[_i];
                    pe->applied = TRUE;
                    DEBUG_PATCH("  Crash recovery: forced original bytes + applied=TRUE for id=%d", id);
                }
            }
            DEBUG_PATCH("  tabForId[%d]=%d mutexGroup=%d", id, d->tab, d->mutex_group);
        } else {
            DEBUG_PATCH("  WARNING: id=%d out of range for tabForId", id);
        }
    }



    /* Force "Shoot Through Walls" to be checked and restored (disabled) on cheat startup.
     * We look for the patch registered with the name "Shoot Through Walls" and restore it. */
    for (int i = 0; i < D2_COUNT; i++) {
        const D2ScanPatch *d = &k_patches[i];
        if (d->name && strcmp(d->name, "Shoot Through Walls") == 0) {
            int id = s_regIds[i];
            if (id >= 0) {
                DEBUG_PATCH("Startup Force-Disable: Reverting 'Shoot Through Walls' (id=%d) to original bytes", id);
                Patch_Restore(id);
            }
            break;
        }
    }

    DEBUG_PATCH("=== D2Patches_Register END ===");
    MUTATE_END
}
#pragma optimize("", on)

