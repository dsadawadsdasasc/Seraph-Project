/* aob_cache.h — persistent disk cache for AOB scan results.
 *
 * All AOB match VAs (and ESP keys) are persisted to a per-machine file
 * %TEMP%\<hash>.tmp (see AobCache_GetPath) keyed by d2base.  ASLR is per-Windows-boot, so within the same boot the
 * cache is valid; across boots d2base changes and cache is invalidated.
 *
 * Schema versioned via AOB_CACHE_VERSION; bump on any field changes.
 */
#ifndef AOB_CACHE_H
#define AOB_CACHE_H

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Both the cache filename AND the file's magic value are derived per-machine
 * from the same FNV-1a hash over (volume serial + computer name).  This means:
 *   - Filename varies host-to-host  → no static string for signature scanners.
 *   - Magic varies host-to-host     → file content has no constant fingerprint
 *                                     (a cache copied from another PC will
 *                                     fail the magic check and be rebuilt).
 * The hash is stable across runs on the same machine, so the cache works as
 * a normal cache locally. */
#define AOB_CACHE_VERSION  37u  /* v37: Dynamic key pre-scan + LocalPlayer & Havok AOBs */


/* Compute the machine-specific 64-bit hash (FNV-1a). */
static __inline UINT64 AobCache_MachineHash(void) {
    UINT64 h = 0xcbf29ce484222325ULL;

    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        for (int i = 0; i < 4; i++) {
            h ^= (UINT8)((serial >> (i * 8)) & 0xFFu);
            h *= 0x100000001b3ULL;
        }
    }

    char comp[64] = {0};
    DWORD clen = sizeof(comp);
    if (GetComputerNameA(comp, &clen)) {
        for (DWORD i = 0; i < clen; i++) {
            h ^= (UINT8)comp[i];
            h *= 0x100000001b3ULL;
        }
    }
    /* Defensive: never return 0 (would be ambiguous with "no magic"). */
    if (h == 0) h = 0xfeedfacecafebabeULL;
    return h;
}

/* Per-machine magic — high 32 bits of the hash.  Different on every PC. */
static __inline UINT32 AobCache_Magic(void) {
    return (UINT32)(AobCache_MachineHash() >> 32);
}

/* Build full path to the per-machine cache file.  Returns FALSE on
 * unrecoverable buffer-size or temp-path failure. */
static __inline BOOL AobCache_GetPath(char *path, DWORD path_size) {
    if (!path || path_size < 64) return FALSE;
    path[0] = 0;
    DWORD n = GetTempPathA(path_size, path);
    if (!n || n >= path_size - 32) { path[0] = 0; return FALSE; }

    UINT64 h = AobCache_MachineHash();
    size_t cur = strlen(path);
    /* "<16 lowercase hex>.tmp" → 21 chars including NUL */
    if (cur + 21 >= path_size) { path[0] = 0; return FALSE; }
    sprintf(path + cur, "%016llx.tmp", (unsigned long long)h);
    return TRUE;
}

/* Disk record layout — keep field order stable across releases.
 * Adding fields: place at end, bump AOB_CACHE_VERSION (invalidates prior
 * caches; users will rescan once on next attach). */
typedef struct {
    UINT32 magic;
    UINT32 version;
    UINT64 d2base;

    /* ESP keys (consolidated here from a previously separate file). */
    UINT32 k1, k2, k3, k4;

    /* Resolved values (post-RIP-resolve where applicable) and raw match VAs. */
    UINT64 datum_va;     /* g_EspState.datum_table_va  (post-resolve)        */
    UINT64 cam_aob_va;   /* k_cam_pat match VA          (raw match)          */
    UINT64 hkp_aob_va;   /* k_hkp_pat match VA          (raw match)          */

    /* Feature AOB raw match VAs (consumed by *_SetPreScanResult). */
    UINT64 dmg_va;
    UINT64 hrg_va;
    UINT64 ib_va;
    UINT64 ik_va;
    UINT64 chams_va;     /* k_chams_pat match VA                             */
    UINT64 rof_va;       /* k_rof_pat match VA (Rapid Fire)                  */
    UINT64 gs_va;        /* .data: GameSpeed                                 */
    UINT64 gsize_va;     /* .data: Guardian                                  */

    UINT64 rev_va;       /* Instant Respawn (revive.c)                       */
    UINT64 ia_va;        /* Instant Abilities (instant_abilities.c)          */
    UINT64 ntb_va;       /* No Turn Back (noturnback.c)                      */
    UINT64 nja_va;       /* No Joining Allies (nojoinallies.c)               */
    UINT64 killaura_va;  /* Kill Aura (kill_aura.c)                          */
    UINT64 revw_va;      /* Instant Respawn – write-side AOB (revive.c)      */
    UINT64 view_mat_va;   /* W2S view matrix VA (proj = view+0x40); see esp.h */
    UINT64 aimbot_vis_va;  /* k_vis_pat match VA (aimbot visibility data AOB) */
    UINT64 itar_va;        /* k_itar_pat match VA (Interact Aura)              */
    UINT64 ammo_va;        /* k_ammo_pat match VA (Infinite Ammo)             */
    UINT64 silent_va;      /* k_silent_pat match VA (Silent Aim)              */
    UINT64 norecoil_va;    /* k_norecoil_pat match VA                         */
    UINT64 cloner_va;      /* k_cloner_pat match VA (Player Cloner)           */
    UINT64 brick_va;       /* k_brick_pat match VA (Ammo Brick Spawner)       */
    UINT64 hs_va;          /* k_hs_pat match VA (Handling Speed)              */
    UINT64 movespeed_va;   /* k_ms_pat match VA (Movement Speed)              */
    
    UINT64 patch_vas[32];  /* Cache for d2_patches.c AOBs                     */
    UINT32 patches_valid;  /* Flag to indicate patch_vas are initialized      */
    UINT32 features_valid; /* Flag to indicate feature VAs are initialized    */
    UINT32 timeDateStamp;  /* Destiny 2 PE TimeDateStamp for verification     */
} AobCacheRec;

/* XOR-obfuscate cache data on disk so memory addresses are never visible in plaintext. */
static __inline void AobCache_XorCrypt(AobCacheRec *rec) {
    UINT64 key = AobCache_MachineHash() ^ 0x6A09E667F3BCC908ULL;
    BYTE *b = (BYTE*)rec;
    for (size_t i = 0; i < sizeof(AobCacheRec); i++) {
        b[i] ^= (BYTE)((key >> ((i % 8) * 8)) & 0xFFu) ^ (BYTE)(i * 37);
    }
}

/* Read cache file; returns TRUE iff file exists, magic+version match,
 * d2base matches the requested base, and timeDateStamp matches. On FALSE, *out is zeroed. */
static __inline BOOL AobCache_Read(UINT64 d2base, UINT32 timeDateStamp, AobCacheRec *out) {
    if (!out) return FALSE;
    memset(out, 0, sizeof(*out));
    char path[MAX_PATH];
    if (!AobCache_GetPath(path, sizeof(path))) return FALSE;
    FILE *f = fopen(path, "rb");
    if (!f) return FALSE;
    BOOL rd = (fread(out, sizeof(*out), 1, f) == 1);
    fclose(f);
    if (!rd) { memset(out, 0, sizeof(*out)); return FALSE; }
    AobCache_XorCrypt(out);
    if (out->magic        != AobCache_Magic() ||
        out->version      != AOB_CACHE_VERSION ||
        out->d2base       != d2base ||
        out->timeDateStamp != timeDateStamp) {
        memset(out, 0, sizeof(*out));
        return FALSE;
    }
    return TRUE;
}

/* Write cache file (overwrite).  Always sets magic/version/d2base/timeDateStamp. */
static __inline void AobCache_Write(UINT64 d2base, UINT32 timeDateStamp, AobCacheRec *rec) {
    if (!rec) return;
    rec->magic         = AobCache_Magic();
    rec->version       = AOB_CACHE_VERSION;
    rec->d2base        = d2base;
    rec->timeDateStamp = timeDateStamp;
    AobCacheRec enc = *rec;
    AobCache_XorCrypt(&enc);
    char path[MAX_PATH];
    if (!AobCache_GetPath(path, sizeof(path))) return;
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(&enc, sizeof(enc), 1, f);
    fclose(f);
}

/* Delete the on-disk cache file.
 *
 * CALL THIS ONCE AT PROGRAM STARTUP (before any AobCache_Read).
 *
 * Why this matters:
 *   The cache is keyed by d2base.  d2base changes each Windows boot because
 *   ASLR randomises it.  AobCache_Read() validates d2base and rejects stale
 *   entries — that is safe across reboots.
 *
 *   HOWEVER: within a single Windows boot, if the game is updated and
 *   restarted, ASLR can place the new build at the SAME address as the old
 *   one (ASLR only re-randomises at boot).  In that case:
 *     - d2base  matches  → cache appears valid
 *     - AOB VAs are wrong → every feature init writes to a wrong VA → crash
 *       or silent failure
 *     - patches_valid==1  → D2Patches_Register() skips the live scan and
 *       uses the stale VAs → patches disappear from the menu or BSOD
 *
 *   Deleting the cache at startup eliminates the risk entirely.  The cost is
 *   one full AOB scan per loader launch (a few seconds at most).             */
static __inline void AobCache_Delete(void) {
    char path[MAX_PATH];
    if (!AobCache_GetPath(path, sizeof(path))) return;
    DeleteFileA(path);
}

#endif /* AOB_CACHE_H */
