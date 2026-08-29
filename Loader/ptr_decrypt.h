#pragma once
#include <windows.h>
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"

/* ── PointerManager::Decrypt + key scanner ───────────────────────────────── *
 *                                                                            *
 * Destiny 2 encrypts some struct pointer fields at runtime using a          *
 * obfuscated XOR+ROL/ROR state machine keyed on three 32-bit values         *
 * (key1, key2, key3) that are embedded as immediate operands in the binary. *
 *                                                                            *
 * AOB patterns to locate the keys (imm32 read from indicated byte offset):  *
 *   key1: E8 ? ? ? ? 8B C8 BD ?? ?? ?? ??   imm32 at pattern+8             *
 *   key2: E8 ? ? ? ? 8B D8 BD ?? ?? ?? ??   imm32 at pattern+8             *
 *   key3: E8 ? ? ? ? 8B F8 BA ?? ?? ?? ??   imm32 at pattern+8             *
 *                                                                            *
 * Usage:                                                                     *
 *   PtrDecrypt_Keys keys = {0};                                              *
 *   if (PtrDecrypt_ScanKeys(cr3, d2base, &keys)) {                          *
 *       UINT64 real = PtrDecrypt_Decrypt(&keys, encrypted_va, cr3);         *
 *   }                                                                        *
 * ─────────────────────────────────────────────────────────────────────────── */

typedef struct {
    UINT32 key1;
    UINT32 key2;
    UINT32 key3;
    UINT32 key4;
    BOOL   valid;
} PtrDecrypt_Keys;

/* ── internal rotate helpers ─────────────────────────────────────────────── */
static inline UINT64 _pd_ror64(UINT64 v, int n) {
    n &= 63;
    return n ? ((v >> n) | (v << (64 - n))) : v;
}
static inline UINT64 _pd_rol64(UINT64 v, int n) {
    n &= 63;
    return n ? ((v << n) | (v >> (64 - n))) : v;
}

/* ── key scanner ─────────────────────────────────────────────────────────── *
 * Scans d2base+0 .. d2base+SCAN_LEN for each AOB pattern and reads the     *
 * imm32 at the appropriate offset.                                          *
 *                                                                           *
 * AOB patterns (from Zydis/Rust scanner, confirmed working):                *
 *   key1: E8 ?? ?? ?? ?? 8B C8 BD   imm32 @ +8                             *
 *   key2: E8 ?? ?? ?? ?? 8B D8 BD   imm32 @ +8                             *
 *   key3: E8 ?? ?? ?? ?? 8B F8 BA   imm32 @ +8                             *
 *   key4: E8 ?? ?? ?? ?? 48 63 D0 BE imm32 @ +8                            */
static inline BOOL PtrDecrypt_ScanKeys(UINT64 cr3, UINT64 d2base,
                                        PtrDecrypt_Keys *out)
{
    const UINT64 SCAN_LEN = 0x8000000ULL; /* 128 MB */

    /* key1: E8 ?? ?? ?? ?? 8B C8 BD */
    static const UINT8 pat1[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xC8, 0xBD };
    static const UINT8 msk1[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
    /* key2: E8 ?? ?? ?? ?? 8B D8 BD */
    static const UINT8 pat2[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD8, 0xBD };
    static const UINT8 msk2[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
    /* key3: E8 ?? ?? ?? ?? 8B F8 BA   (Zydis confirmed, imm32 @ +8) */
    static const UINT8 pat3[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF8, 0xBA };
    static const UINT8 msk3[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
    /* key4: E8 ?? ?? ?? ?? 48 63 D0 BE   (imm32 @ +8) */
    static const UINT8 pat4[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x63, 0xD0, 0xBE };
    static const UINT8 msk4[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

    UINT64 va1 = 0, va2 = 0, va3 = 0, va4 = 0;

    BYOVD_LOCK();
    va1 = BYOVD_ScanPatternText(cr3, d2base, pat1, msk1, 8);
    va2 = BYOVD_ScanPatternText(cr3, d2base, pat2, msk2, 8);
    va3 = BYOVD_ScanPatternText(cr3, d2base, pat3, msk3, 8);
    va4 = BYOVD_ScanPatternText(cr3, d2base, pat4, msk4, 9);
    BYOVD_UNLOCK();

    if (!va1 || !va2 || !va3) { /* key4 is optional (fallback) */
        if (!va1 && !va2 && !va3) return FALSE;
    }

    UINT32 k1 = 0, k2 = 0, k3 = 0, k4 = 0;
    BYOVD_LOCK();
    if (va1) BYOVD_ReadVA(cr3, va1 + 8, &k1, 4);
    if (va2) BYOVD_ReadVA(cr3, va2 + 8, &k2, 4);
    if (va3) BYOVD_ReadVA(cr3, va3 + 8, &k3, 4);
    if (va4) BYOVD_ReadVA(cr3, va4 + 8, &k4, 4);
    BYOVD_UNLOCK();

    out->key1  = k1;
    out->key2  = k2;
    out->key3  = k3;
    out->key4  = k4;
    out->valid = (k1 && k2 && k3) ? TRUE : FALSE;
    return TRUE;
}

/* ── PtrDecrypt_Decrypt ───────────────────────────────────────────────────── *
 * Reads 8 bytes from encryptedVA, applies the PointerManager::Decrypt       *
 * state machine, and returns the real pointer.                               *
 * Returns 0 if the read fails or the result is 0.                            */
static inline UINT64 PtrDecrypt_Decrypt(const PtrDecrypt_Keys *keys,
                                         UINT64 encryptedVA,
                                         UINT64 cr3)
{
    if (!keys || !keys->valid || !encryptedVA) return 0;

    UINT64 raw = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, encryptedVA, &raw, 8);
    BYOVD_UNLOCK();
    if (!raw) return 0;

    /* step 1: apply key1 (low 32) and key2 (high 32) XOR */
    UINT32 lo = (UINT32)(raw & 0xFFFFFFFFULL);
    UINT32 hi = (UINT32)(raw >> 32);
    UINT64 v0 = (UINT64)(lo ^ keys->key1) |
                ((UINT64)(hi ^ keys->key2) << 32);
    if (!v0) return 0;

    /* step 2: key3 state machine  (direct C port of the IDA pseudocode) */
    int      v2  = (int)keys->key3;
    UINT32   v3  = 1793588203u;
    UINT64   v6  = _pd_ror64((UINT64)(UINT32)v2, 12) & 0xFULL;
    int      v5  = 2140909415;

    for (;;) {
        if (v3 == 1449317815u) return v0;

        if (v3 == 1793588203u) { v5 = -2023550482; goto lbl74; }

        if (v3 > 0x6AE7FBEBu) {
            if (v3 > 0xB8E1B51Du) {
                if (v3 <= 0xED84EA05u) {
                    switch (v3) {
                    case 0xED84EA05u: v6 ^= 0x86D5EE4ULL;  v5 = 2015727729;   break;
                    case 0xCDD87D06u: v6 ^= 0x772FD793ULL; v5 = -1539837777;  break;
                    case 0xD1C42575u: v5 = -1143685397; v6 = (UINT32)v0 ^ 0x696AAB0u;
                                      v0 = _pd_rol64(v0, 32); break;
                    case 0xE8774282u: v0 = _pd_rol64(v0, 32); v5 = 1631872807; break;
                    }
                    goto lbl75;
                }
                if (v3 == 0xEF07B245u) { v5 = -354324759; }
                else if (v3 == 0xF0A7CA2Au) { v0 ^= v6; v5 = -491447893; goto lbl74; }
                else if (v3 == 0xF90D4B68u) { v6 ^= 0x4AE7CAAull; v5 = -415810604; v0 = _pd_rol64(v0, 32); }
                goto lbl75;
            }
            if (v3 == 0xB9B2601Du) {
                v5 = 1951937120;
                v6 = (UINT32)v0 ^ 0x8A7CC1D2u;
                v0 = _pd_ror64(v0, 32);
            } else if (v3 > 0xA7CC20F3u) {
                switch (v3) {
                case 0xA9385526u: v5 = 191258389; v6 = (UINT32)v0 ^ 0x3FE0348Fu; break;
                case 0xB457BF21u: v0 ^= v6; v5 = -4167565;  break;
                case 0xB6F8595Au: v6 ^= 0x46EE364ULL; v5 = 45082235; v0 = _pd_rol64(v0, 32); break;
                }
                goto lbl75;
            } else if (v3 == 0xA695FB33u) { v6 ^= 0xBB569BCULL; v5 = -1376774281; }
            else if (v3 == 0x741F26DCu) { v5 = -12720683; v6 = (UINT32)v0 ^ 0x669F174Bu; }
            else if (v3 == 0x792BCA65u) { v0 ^= v6; v5 = 1070300415; goto lbl74; }
            else if (v3 == 0x898EE925u) { v5 = -957507448; v6 = (UINT32)v0 ^ 0x97DFB4Au; }
            else if (v3 == 0x9550B134u) { v0 = _pd_rol64(v0, 32); v5 = -1919001445; }
            else { v0 ^= v6; v5 = 1070300415; goto lbl74; }
            goto lbl75;
        }

        if (v3 <= 0x365D069Au) {
            if (v3 == 0x365D069Au) { v0 ^= v6; v5 = 122161898; }
            else if (v3 <= 0x135F573Au) {
                switch (v3) {
                case 0x135F573Au: v6 ^= 0xAD81FFF8ULL; v5 = 1959148305; v0 = _pd_rol64(v0, 32); break;
                case 0x05A68EACu: v6 ^= 0x7599584ULL;  v5 = -305017810; break;
                case 0x0A3C3784u: v5 = -2065585065; v0 = v6 ^ _pd_ror64(v0, 32); break;
                case 0x0B9A39A3u: v6 ^= 0x520499FULL; v5 = 88841649; v0 = _pd_ror64(v0, 32); break;
                }
            } else {
                switch (v3) {
                case 0x13B761C1u: v6 ^= 0x3857867FULL; v5 = 1571831026; break;
                case 0x183F26EFu: v0 ^= v6; v5 = -143079766; break;
                case 0x31150C70u: v0 = (UINT32)v0 ^ 0x5C7AB0E6u ^ _pd_rol64(v0, 32);
                                  v5 = -1764152189;
lbl74:                            v6 = (UINT32)v0; break;
                }
            }
            goto lbl75;
        }

        /* v3 in (0x365D069A, 0x6AE7FBEB] */
        if (v3 > 0x49BF5619u) {
            if (v3 == 0x4BC14152u)      { v5 = -2041599404; goto lbl74; }
            else if (v3 == 0x4E124F33u) { v0 = _pd_ror64(v0, 32); v5 = 223073131; }
            else if (v3 == 0x69E87BA9u) { v0 = _pd_rol64(v0, 32); v5 = 1605536563; }
            goto lbl75;
        }
        if (v3 == 0x49BF5619u)      { v6 ^= 0x479EF5ULL; v5 = 1108622031; v0 = _pd_ror64(v0, 32); }
        else if (v3 == 0x43440658u) { v0 ^= v6; v5 = 72627986; }
        else if (v3 == 0x47219D4Au) { /* no-op, fall through */ }
        else if (v3 == 0x480ACC5Bu) { v0 = _pd_rol64(v0, 32); v5 = -1187873999; }
        else {
            /* final exit: ROL 32 */
            return _pd_rol64(v0, 32);
        }

lbl75:
        v3 ^= (UINT32)v5;
    }
}

/* ── PtrDecrypt_DecryptDirect ────────────────────────────────────────────── *
 * Convenience: when you already have the raw encrypted u64 value in hand    *
 * (not a VA to read from), apply just the state machine.                    */
static inline UINT64 PtrDecrypt_DecryptRaw(const PtrDecrypt_Keys *keys,
                                            UINT64 raw)
{
    if (!keys || !keys->valid || !raw) return 0;

    UINT32 lo = (UINT32)(raw & 0xFFFFFFFFULL);
    UINT32 hi = (UINT32)(raw >> 32);
    UINT64 v0 = (UINT64)(lo ^ keys->key1) |
                ((UINT64)(hi ^ keys->key2) << 32);
    if (!v0) return 0;

    /* reuse the same body — call the VA variant with a fake VA of 0 is not
     * possible, so we duplicate the state machine entry here as a thin shim */
    PtrDecrypt_Keys tmp = *keys;
    /* abuse: write raw into a local, pass a local VA trick is not available
     * in pure C without VLA.  Instead, inline the same state machine start: */

    int    v2 = (int)tmp.key3;
    UINT32 v3 = 1793588203u;
    UINT64 v6 = _pd_ror64((UINT64)(UINT32)v2, 12) & 0xFULL;
    int    v5 = 2140909415;

    for (;;) {
        if (v3 == 1449317815u) return v0;
        if (v3 == 1793588203u) { v5 = -2023550482; v6 = (UINT32)v0; goto sm75; }

        if (v3 > 0x6AE7FBEBu) {
            if (v3 > 0xB8E1B51Du) {
                if (v3 <= 0xED84EA05u) {
                    switch (v3) {
                    case 0xED84EA05u: v6 ^= 0x86D5EE4ULL;  v5 = 2015727729;   break;
                    case 0xCDD87D06u: v6 ^= 0x772FD793ULL; v5 = -1539837777;  break;
                    case 0xD1C42575u: v5 = -1143685397; v6 = (UINT32)v0 ^ 0x696AAB0u; v0 = _pd_rol64(v0,32); break;
                    case 0xE8774282u: v0 = _pd_rol64(v0,32); v5 = 1631872807; break;
                    }
                    goto sm75;
                }
                if (v3 == 0xEF07B245u)      { v5 = -354324759; }
                else if (v3 == 0xF0A7CA2Au) { v0 ^= v6; v5 = -491447893; v6 = (UINT32)v0; goto sm75; }
                else if (v3 == 0xF90D4B68u) { v6 ^= 0x4AE7CAAull; v5 = -415810604; v0 = _pd_rol64(v0,32); }
                goto sm75;
            }
            if (v3 == 0xB9B2601Du) { v5 = 1951937120; v6 = (UINT32)v0 ^ 0x8A7CC1D2u; v0 = _pd_ror64(v0,32); }
            else if (v3 > 0xA7CC20F3u) {
                switch (v3) {
                case 0xA9385526u: v5 = 191258389; v6 = (UINT32)v0 ^ 0x3FE0348Fu; break;
                case 0xB457BF21u: v0 ^= v6; v5 = -4167565; break;
                case 0xB6F8595Au: v6 ^= 0x46EE364ULL; v5 = 45082235; v0 = _pd_rol64(v0,32); break;
                }
                goto sm75;
            } else if (v3 == 0xA695FB33u) { v6 ^= 0xBB569BCULL; v5 = -1376774281; }
            else if (v3 == 0x741F26DCu)   { v5 = -12720683; v6 = (UINT32)v0 ^ 0x669F174Bu; }
            else if (v3 == 0x792BCA65u)   { v0 ^= v6; v5 = 1070300415; v6 = (UINT32)v0; goto sm75; }
            else if (v3 == 0x898EE925u)   { v5 = -957507448; v6 = (UINT32)v0 ^ 0x97DFB4Au; }
            else if (v3 == 0x9550B134u)   { v0 = _pd_rol64(v0,32); v5 = -1919001445; }
            else { v0 ^= v6; v5 = 1070300415; v6 = (UINT32)v0; goto sm75; }
            goto sm75;
        }

        if (v3 <= 0x365D069Au) {
            if (v3 == 0x365D069Au) { v0 ^= v6; v5 = 122161898; }
            else if (v3 <= 0x135F573Au) {
                switch (v3) {
                case 0x135F573Au: v6 ^= 0xAD81FFF8ULL; v5 = 1959148305; v0 = _pd_rol64(v0,32); break;
                case 0x05A68EACu: v6 ^= 0x7599584ULL; v5 = -305017810; break;
                case 0x0A3C3784u: v5 = -2065585065; v0 = v6 ^ _pd_ror64(v0,32); break;
                case 0x0B9A39A3u: v6 ^= 0x520499FULL; v5 = 88841649; v0 = _pd_ror64(v0,32); break;
                }
            } else {
                switch (v3) {
                case 0x13B761C1u: v6 ^= 0x3857867FULL; v5 = 1571831026; break;
                case 0x183F26EFu: v0 ^= v6; v5 = -143079766; break;
                case 0x31150C70u: v0 = (UINT32)v0 ^ 0x5C7AB0E6u ^ _pd_rol64(v0,32); v5 = -1764152189;
sm74:                             v6 = (UINT32)v0; break;
                }
            }
            goto sm75;
        }

        if (v3 > 0x49BF5619u) {
            if (v3 == 0x4BC14152u)      { v5 = -2041599404; goto sm74; }
            else if (v3 == 0x4E124F33u) { v0 = _pd_ror64(v0,32); v5 = 223073131; }
            else if (v3 == 0x69E87BA9u) { v0 = _pd_rol64(v0,32); v5 = 1605536563; }
            goto sm75;
        }
        if (v3 == 0x49BF5619u)      { v6 ^= 0x479EF5ULL; v5 = 1108622031; v0 = _pd_ror64(v0,32); }
        else if (v3 == 0x43440658u) { v0 ^= v6; v5 = 72627986; }
        else if (v3 == 0x480ACC5Bu) { v0 = _pd_rol64(v0,32); v5 = -1187873999; }
        else { return _pd_rol64(v0,32); }

sm75:
        v3 ^= (UINT32)v5;
    }
}
