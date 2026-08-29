#pragma once

/* ── Decryption Key AOB Patterns ─────────────────────────────────────────── */
/* esp.h -- Destiny 2 TigerList ESP
 *
 * All ESP is driven exclusively by the TigerList (PObject array).
 * No SObject pool, no component chain walk.
 *
 * ── Pointer decryption (PointerManager::Decrypt) ────────────────────────────
 *   AOB key1 : E8 ?? ?? ?? ?? 8B C8 BD   imm32 at +8
 *   AOB key2 : E8 ?? ?? ?? ?? 8B D8 BD   imm32 at +8
 *   AOB key3 : E8 ?? ?? ?? ?? 8B F8 BA   imm32 at +8
 *   AOB key4 : E8 ?? ?? ?? ?? 48 63 D0 BE imm32 at +9  (cff_decrypt_float, HP only)
 *
 * ── Datum (handle) resolution ────────────────────────────────────────────
 *   AOB sig  : 48 8B 05 ?? ?? ?? ?? BD
 *   idx      = ((salt | 0xFFC0000) >> 18) & salt   (salt = h >> 13)
 *   v10      = datum_table + idx * 64
 *   v11      = entry_base + stride * (h & 0x1FFF)
 *   resolved = v11 - (*(u64*)(v11+8) & (u64)(i32)adj)
 *
 * ── TigerList slot layout (stride 0x4F20) ────────────────────────────────
 *   +0x004  u32  handle to Schindler's list entity (pos/team via SL)
 *   +0x020  u32  LP marker (0x140 = local player)
 *   +0x140  u32  bone count  (direct, no handle resolution)
 *   +0x180  bone[0]  (stride 0x20; bone+0x10=X, +0x14=Y, +0x18=Z)
 *   +0x440  float[3] world position — LOCAL PLAYER ONLY (plaintext, DO NOT read for enemies)
 *   +0x4610 u32  bone transforms handle (maybe)
 *   +0x4688 u32  bone array handle
 *   +0x4620 u32  health handle
 *   +0x9D4  encrypted name
 *   +0xA24  u32  team ID
 */

#include <windows.h>
#include <emmintrin.h>
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "aob_cache.h"
#include "aob_patterns.h"
#include "skeleton.h"
#include "local_player.h"

/* ── TigerList player array ─────────────────────────────────────────────── */
#define TL_MAX_SLOTS    16
#ifndef TL_STRIDE
#define TL_STRIDE       0x4F20ULL  /* matches tigerlist.h */
#endif
#define TL_OFF_LP_CHECK 0x20u
#define TL_LP_MARKER    0x140u
#define TL_OFF_BONE_ARR 0x48A0u    /* bone datum handle — matches tigerlist.h TL_OFF_BONE_HDL */
#define TL_BONE_COUNT   0x140u
#define TL_BONE_FIRST   0x180u
#define TL_BONE_STRIDE  0x20u
#define TL_BONE_OFF_X   0x10u
#define TL_BONE_OFF_Y   0x14u
#define TL_BONE_OFF_Z   0x18u

/* ── Types ───────────────────────────────────────────────────────────────── */
typedef struct { float x, y, z; } EspVec3;

#ifndef ESP_STATE_DEFINED
#define ESP_STATE_DEFINED
typedef struct {
    UINT64  datum_table_va;
    UINT32  key1;
    UINT32  key2;
    UINT32  key3;
    UINT32  key4;
    BOOL    keys_valid;
    BOOL    datum_valid;
    UINT64  view_mat_va;
    UINT64  proj_mat_va;
    BOOL    matrices_valid;
    UINT64  g_players_va;
    BOOL    tl_valid;
} EspState;

#ifdef __cplusplus
extern "C" EspState g_EspState;
#else
extern EspState g_EspState;
#endif
#endif /* ESP_STATE_DEFINED */

#ifndef WRITE_ESP_LOG_DEFINED
#define WRITE_ESP_LOG_DEFINED
/* ── Direct file log (debug-only) ───────────────────────────────────────── */
#ifndef NDEBUG
#define WriteEspLog(msg) DEBUG_ESP("%s", msg)
#else
#define WriteEspLog(x) ((void)0)
#endif
#endif /* WRITE_ESP_LOG_DEFINED */

#ifndef DATUM_ROW_DATA_DEFINED
#define DATUM_ROW_DATA_DEFINED
#pragma pack(push, 1)
typedef struct {
    UINT64 entry_base;
    UINT8  pad_10[0x20];
    UINT32 stride;
    INT32  adj; 
} DatumRowData;
#pragma pack(pop)
#endif

/* Tiger datum handle pattern: byte 2 (mask 0x00FF0000) == 0xF9. Used to
 * pre-filter values before calling esp_datum_resolve so that sizes,
 * type-hashes (0x80XXXXXX), and other non-handle u32s are rejected. */
static __inline BOOL is_tiger_handle(UINT32 h)
{
    return h && h != 0xFFFFFFFFu && !(h & 0x80000000u);
}

/* ── esp_datum_resolve ───────────────────────────────────────────────────── *
 * Resolves a 32-bit Tiger handle into a component pointer using the datum
 * table scanned by ESP_Init into g_EspState.datum_table_va.
 * Available to all translation units that include esp.h.
 * ─────────────────────────────────────────────────────────────────────────── */
/* Per-idx DatumRowData cache: the datum table layout for a given idx is
 * stable within a session (it only changes on game update). Caching avoids
 * the 2 BYOVD IOCTLs (row + mask reads) for repeated calls with the same idx,
 * which is the common case when iterating 16 TL slots every frame.
 * Cache holds up to 64 unique idx entries; evicted when datum_table_va changes. */
#define _ESP_DATUM_CACHE_N 64
typedef struct { UINT32 idx; UINT64 entry_base; UINT32 stride; INT32 adj; BOOL valid; } _DatumRowCache;
static _DatumRowCache _datum_cache[_ESP_DATUM_CACHE_N];
static UINT64 _datum_cache_base = 0;  /* invalidate when table VA changes */

static __inline UINT64 esp_datum_resolve_ext(UINT64 cr3, UINT32 h, BOOL logThis)
{
    if (h == 0u || h == 0xFFFFFFFFu || !g_EspState.datum_valid) return 0;

    UINT32 idx = (((h >> 13) | 0xFFC0000u) >> 18u) & (h >> 13);
    if (idx > 0x15000ULL) return 0;

    /* Invalidate cache if datum table VA changed (e.g. game update between sessions) */
    if (_datum_cache_base != g_EspState.datum_table_va) {
        _datum_cache_base = g_EspState.datum_table_va;
        for (int _ci = 0; _ci < _ESP_DATUM_CACHE_N; _ci++) _datum_cache[_ci].valid = FALSE;
    }

    /* Look up cached row for this idx */
    int _slot = (int)(idx % _ESP_DATUM_CACHE_N);
    DatumRowData row = {0};
    BOOL cacheHit = FALSE;
    if (_datum_cache[_slot].valid && _datum_cache[_slot].idx == idx) {
        /* Cache hit: reuse entry_base/stride/adj, only read per-handle mask */
        row.entry_base = _datum_cache[_slot].entry_base;
        row.stride     = _datum_cache[_slot].stride;
        row.adj        = _datum_cache[_slot].adj;
        cacheHit = TRUE;
    } else {
        /* Cache miss: read row from BYOVD */
        UINT64 v10 = g_EspState.datum_table_va + (UINT64)idx * 64ULL;
        BYOVD_LOCK();
        BYOVD_ReadVA_NoCache(cr3, v10 + 8, &row, sizeof(row));
        BYOVD_UNLOCK();
        if (logThis) {
            char _db[180];
            wsprintfA(_db, "[RESOLVE_DBG] miss: idx=0x%X v10=0x%I64X entry=0x%I64X stride=%u adj=%d",
                      idx, v10, row.entry_base, row.stride, row.adj);
            WriteEspLog(_db);
        }
        if (!row.entry_base) return 0;
        /* Store in cache */
        _datum_cache[_slot].idx        = idx;
        _datum_cache[_slot].entry_base = row.entry_base;
        _datum_cache[_slot].stride     = row.stride;
        _datum_cache[_slot].adj        = row.adj;
        _datum_cache[_slot].valid      = TRUE;
    }

    if (logThis && cacheHit) {
        char _db[180];
        wsprintfA(_db, "[RESOLVE_DBG] hit: idx=0x%X entry=0x%I64X stride=%u adj=%d",
                  idx, row.entry_base, row.stride, row.adj);
        WriteEspLog(_db);
    }

    if (!row.entry_base) return 0;

    UINT64 v11  = row.entry_base + (UINT64)row.stride * (UINT64)(h & 0x1FFFu);
    UINT64 mask = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, v11 + 8, &mask, 8);
    BYOVD_UNLOCK();

    UINT64 ptr = v11 - (mask & (UINT64)(INT64)row.adj);
    if (logThis) {
        char _db[180];
        wsprintfA(_db, "[RESOLVE_DBG] slot: v11=0x%I64X mask=0x%I64X ptr=0x%I64X",
                  v11, mask, ptr);
        WriteEspLog(_db);
    }
    return (ptr > 0x100000ULL && ptr < 0x800000000000ULL) ? ptr : 0;
}

static __inline UINT64 esp_datum_resolve(UINT64 cr3, UINT32 h)
{
    return esp_datum_resolve_ext(cr3, h, FALSE);
}

/* ── Coordinate log AOB (ground-truth validation) ───────────────────────── *
 * Located at the player_position_x log site in the Tiger Engine coord path.  *
 * Seen at .text:7FF60B644199 (April 2026 build).                             *
 *   31 44 24 3C        XOR [rsp+3Ch], eax   ; eax = decrypted X float bits   *
 *   4C 8D 05 ?? ?? ??  LEA r8, "player_position_x"                           *
 * The call to cff_decrypt_float (key4 consumer) precedes this by ~7 bytes.   *
 *                                                                             *
 * Havok RigidBody coordinate layout (same world space, same axis order):     *
 *   rb_base + 0x1C0  float  X (east)                                         *
 *   rb_base + 0x1C4  float  Y (north)                                        *
 *   rb_base + 0x1C8  float  Z (height)                                       *
 * Tiger ECS SObject enc_pos (SOBJ_OFF_ENC_POS = 0xD0, 3x u32):               *
 *   enc[0] → X (east)   enc[1] → Y (north)   enc[2] → Z (height)            *
 * Both share the same world-space axes — numeric values must match.          *
 * ─────────────────────────────────────────────────────────────────────────── */
#define ESP_AOB_COORD_LOG         "\x31\x44\x24\x3C\x4C\x8D\x05"
#define ESP_MASK_COORD_LOG        "xxxxxxx????"
#define ESP_AOB_COORD_LOG_LEN     11

#define ESP_RB_OFF_X              0x1C0u   /* Havok RigidBody east   */
#define ESP_RB_OFF_Y              0x1C4u   /* Havok RigidBody north  */
#define ESP_RB_OFF_Z              0x1C8u   /* Havok RigidBody height */
#define ESP_COORD_VALIDATE_THRESH 1.5f     /* max per-axis delta for valid match */

/* ── World→Screen view/proj matrix anchor (.text scan) ────────────────────── *
 * Anchor sequence (21 bytes): three consecutive lea instructions:
 *
 *   48 8D 15 ?? ?? ?? ??   lea  rdx, [rip+disp32]   ← viewMatrix ptr (THIS one)
 *   48 8D 0D ?? ?? ?? ??   lea  rcx, [rip+disp32]   (camera struct — not decoded)
 *   48 8D 35 ?? ?? ?? ??   lea  rsi, [rip+disp32]   (auxiliary — not decoded)
 *
 * The match VA points at the first `lea rdx`, whose RIP-relative target IS
 * the viewMatrix start address. projMatrix lives 0x40 bytes after:
 *   viewMatrix VA  = match + 7 + disp32
 *   projMatrix VA  = viewMatrix VA + 0x40
 *
 * Final VAs cached in g_EspState.view_mat_va / proj_mat_va.                  */
#define ESP_AOB_W2S         "\x48\x8D\x15\x00\x00\x00\x00" \
                            "\x48\x8D\x0D\x00\x00\x00\x00" \
                            "\x48\x8D\x35\x00\x00\x00\x00"
#define ESP_MASK_W2S        "xxx????xxx????xxx????"
#define ESP_AOB_W2S_LEN     21
#define ESP_W2S_LEA_OFFSET  0x00u    /* lea rdx is at match[0..6]             */
#define ESP_W2S_LEA_SIZE    7u       /* 48 8D 15 + disp32                     */
#define ESP_W2S_OFF_VIEW    0x000u   /* viewMatrix IS at the decoded address   */
#define ESP_W2S_OFF_PROJ    0x040u   /* projMatrix = viewMatrix + 0x40        */
#define ESP_MAT4_BYTES      64u      /* 16 floats per matrix                  */

/* Hardcoded player FOV (horizontal degrees).  Destiny 2 in-game slider caps
 * at 105°; we always assume the user runs at that ceiling.  Pre-computed
 * tan(FOV/2) used by the FOV-based W2S projection (see ESP_WorldToScreen_FOV). */
#define ESP_DEFAULT_FOV_DEG 105.0f
#define ESP_DEFAULT_FOV_TAN 1.30322537284f   /* tanf(105° * 0.5 * π/180)      */
#define ESP_ASPECT_16_9     1.77777777778f   /* 16/9 vertical compensation    */

/* ── Public API ──────────────────────────────────────────────────────────── */
#ifdef __cplusplus
extern "C" {
#endif

/* Scan for datum_table and decryption keys. Call after game attach.
 * Returns TRUE if at least datum_table + key4 resolved (position decrypt). */
BOOL ESP_Init(void);
BOOL Keys_Init(void);

/* Invalidate all state. Call on detach / game exit. */
void ESP_Reset(void);

/* Decrypt a 64-bit pointer stored at enc_field_va using keys 1-3.
 * Returns 0 on failure or if keys not ready. */
UINT64 ESP_DecryptPtr(UINT64 cr3, UINT64 enc_field_va);

/* Decrypt a single encrypted float using key4.
 * Pass the raw u32 value already read from memory. */
float  ESP_DecryptFloat(UINT32 encrypted);

/* Faithful one-shot trace of decryptor state machine — logs to decrypt_trace.log */
void   Esp_TraceDecrypt(UINT64 cr3, UINT64 encVA,
                        UINT32 k1, UINT32 k2, UINT32 k3, UINT32 k4);

/* ── W2S (World→Screen) ──────────────────────────────────────────────────── *
 * Resolve view/proj matrix VAs by scanning the W2S anchor AOB and decoding
 * the lea rcx,[rip+disp32] at match+0x19.  Populates
 *   g_EspState.view_mat_va, g_EspState.proj_mat_va, g_EspState.matrices_valid
 * Returns TRUE on success.  Idempotent — safe to call from a tick if matrices
 * weren't ready at attach time.                                             */
BOOL   ESP_ResolveMatrices(void);

/* Read both 4x4 matrices from game memory in a single locked pass.
 * Caller provides 16-float buffers for view and proj.  Returns TRUE on
 * success; FALSE if matrices_valid is FALSE or BYOVD reads fail.            */
BOOL   ESP_ReadMatrices(float view[16], float proj[16]);

/* Hard cap on entity boxes returned per frame — sized to match Havok's
 * HAVOK_MAX_RESULTS so we never silently drop entities at the API boundary. */
#define ESP_MAX_BOXES 256

/* ── Per-entity box for the overlay.  cx/cy is the screen-space center, w/h
 * the box dimensions in pixels, dist the distance from the camera in world
 * units (used by the renderer to scale colors / alpha by range).            */
typedef struct {
    float    cx, cy;
    float    w, h;
    float    dist;
    UINT64   entity_ptr;     /* bone component VA */
    INT32    team;           /* 0=ally  1=enemy  -1=unknown */
    float    worldX, worldY, worldZ; /* world-space position (bone[0]) */
} EspBox;


/* Project every Havok entity in the world (except the local player) into
 * screen space and return up to max_out visible boxes.  Internally calls
 * Havok_GetEntities at most every 150 ms (cached between calls), then
 * re-reads the live RB coords each frame so moving entities track smoothly.
 *
 * Returns the number of boxes written to `out`.  0 on failure / no entities
 * / matrices not yet resolved.                                              */
int    ESP_GetEntityBoxes(int screen_w, int screen_h, EspBox *out, int max_out);

/* Scan Schindler's List (player definitions) and log findings.
 * Call every render frame; internally throttled to 5s intervals.           */
void   ESP_ScanSchindler(void);

/* Returns the last resolved Schindler's List base pointer (0 if not yet found). */
UINT64 ESP_GetSLListBase(void);

/* Project a world-space point through view×proj into screen pixels.
 * view, proj: row-major 4x4 (as stored by the engine).
 * (wx, wy, wz): world coordinates.
 * (screen_w, screen_h): client area dimensions in pixels.
 * Outputs *out_x, *out_y on success.
 * Returns FALSE if behind the camera (clip.w <= near plane epsilon).        */
BOOL   ESP_WorldToScreen(const float view[16], const float proj[16],
                         float wx, float wy, float wz,
                         int screen_w, int screen_h,
                         float *out_x, float *out_y);

/* Alternate FOV-based W2S — mirrors the public Destiny 2 implementation
 * shared on UnknownCheats.  Uses ONLY the view matrix as a camera-world
 * transform (rows 0..2 = right/up/forward basis, row 3 = camera position)
 * and a hardcoded horizontal FOV of 105° (see ESP_DEFAULT_FOV_TAN).
 * Useful as a fallback if the proj-matrix variant produces wrong results. */
BOOL   ESP_WorldToScreen_FOV(const float view[16],
                             float wx, float wy, float wz,
                             int screen_w, int screen_h,
                             float *out_x, float *out_y);

/* TigerList plaintext local-player coords reader (defined in fly.c).
 * Returns TRUE with out[3] filled when the local-marker entry is found
 * in the PObjects array, FALSE during transitional windows.             */
BOOL   Fly_ReadLocalCoordsTL(float out[3]);

/* Cached matrix access — filled by background thread in esp.c */
BOOL  ESP_GetCachedMatrices(float view[16], float proj[16]);
void  ESP_StartUpdateThread(void);
void  ESP_StopUpdateThread(void);
/* Ref-counted wrappers: each caller Acquire on start, Release on stop.
 * Thread starts when count goes 0→1, stops when 1→0.              */
void  ESP_AcquireUpdateThread(void);
void  ESP_ReleaseUpdateThread(void);

/* Inline float helpers used by skeleton/tigerlist */
#ifndef _VEC_OK_DEFINED
#define _VEC_OK_DEFINED
static __inline int _finite_f(float v) {
    unsigned u; memcpy(&u, &v, 4);
    return (u & 0x7F800000u) != 0x7F800000u;
}
static __inline int _vec_ok(float x, float y, float z) {
    return _finite_f(x) && _finite_f(y) && _finite_f(z)
        && (x*x + y*y + z*z) > 0.01f
        && (x > -1e5f && x < 1e5f)
        && (y > -1e5f && y < 1e5f)
        && (z > -1e5f && z < 1e5f);
}
#endif

#ifdef __cplusplus
}
#endif


/* ════════════════════════════════════════════════════════════════════════════
 * IMPLEMENTATION  (define ESP_IMPLEMENTATION in exactly one .c file)
 * ════════════════════════════════════════════════════════════════════════════ */
#ifdef ESP_IMPLEMENTATION

#include <math.h>   /* fabsf, NaN check */
#include <string.h> /* memset, memcmp   */
#include <stdio.h>  /* FILE, fopen — disk key cache */
#include "lists.h"    /* HavokEntity / Havok_GetEntities / g_HavokState */
#include "fly.h"      /* Fly_GetPObjDecryptedVA — TigerList container ptr */
#include "sobject.h"  /* TLIST_* offsets (April 2026 build)               */
#include "ptr_decrypt.h"



/* ── Global state ────────────────────────────────────────────────────────── */
EspState g_EspState = {0};


static DWORD s_espLogLastMs = 0;
static BOOL  s_espLogInit   = FALSE;

/* ── Rotate helpers ──────────────────────────────────────────────────────── */
static __inline UINT32 _esp_rol32(UINT32 v, int n) {
    return (v << n) | (v >> (32 - n));
}
static __inline UINT32 _esp_ror32(UINT32 v, int n) {
    return (v >> n) | (v << (32 - n));
}
static __inline UINT64 _esp_rol64(UINT64 v, int n) {
    return (v << n) | (v >> (64 - n));
}
static __inline UINT64 _esp_ror64(UINT64 v, int n) {
    return (v >> n) | (v << (64 - n));
}

/* ── cff_decrypt_float ───────────────────────────────────────────────────── *
 * Decrypts a single 32-bit encrypted HP (health/shield) value.
 * key4 AOB: E8 ?? ?? ?? ?? 33 E8 E8  (imm32 at +9 from match)
 * NOTE: this function is for HP only. SObject position (+0xD0) uses a
 *       DIFFERENT unknown encryption — do NOT use this for position decryption.
 *
 * State machine trace:
 *   ecx = state (starts 0x4393ADDD), edx = accumulator, ebx = working value
 *   Advances via ecx ^= eax (next-state constant from switch).
 *   Terminates when ecx == 0xD255BB56: ebx ^= edx; rol32(ebx,16); ebx ^= key4.
 * ─────────────────────────────────────────────────────────────────────────── */
float ESP_DecryptFloat(UINT32 encrypted)
{
    UINT32 ebx = encrypted;
    UINT32 ecx = 0x4393ADDDu;
    UINT32 edx = 0u;
    UINT32 eax = 0u;

    for (int guard = 0; guard < 64; guard++) {
        if (ecx == 0xD255BB56u) {
            ebx ^= edx;
            ebx  = _esp_rol32(ebx, 16);
            ebx ^= g_EspState.key4;
            return *(float*)&ebx;
        }
        switch (ecx) {
            case 0x4393ADDDu:
                eax = 0xAB984326u;
                edx = (UINT32)(UINT16)ebx;          /* movzx edx, bx          */
                break;
            case 0x059FCC87u:
                eax = 0x91CF90BCu;
                ebx = _esp_rol32(ebx, 16);
                edx = (UINT32)(UINT16)(ebx ^ 0x5340u);
                break;
            case 0xCCD630EDu:
                edx ^= 0x4AC5u;
                eax  = 0x1E838BBBu;
                ebx  = _esp_ror32(ebx, 16);
                break;
            case 0xE80BEEFBu:
                edx ^= 0x9DE8u;
                eax  = 0x1CF9DC4Eu;
                ebx  = _esp_ror32(ebx, 16);
                break;
            case 0xFB91CDDAu:
                edx = (UINT32)(UINT16)(ebx ^ 0xFFFF89C6u);
                eax = 0x7FBB741Au;
                ebx = _esp_rol32(ebx, 16);
                break;
            case 0xF4F232B5u:
                ebx ^= edx;
                eax  = 0x05569343u;
                break;
            case 0xF1A4A1F6u:
                eax = 0x3D72911Bu;
                edx = (UINT32)(UINT16)ebx;
                break;
            default:
                return 0.0f;   /* unknown state — bail */
        }
        ecx ^= eax;
    }
    return 0.0f;
}

/* ── ESP_DecryptPtr_Core ─────────────────────────────────────────────────── *
 * State machine for sub_7FF66F80EF10 (PointerManager::Decrypt).  Constants
 * verified 1:1 against disassembly — see Esp_TraceDecrypt for the same logic
 * with per-iteration logging.  Returns plaintext pointer, or 0 on failure.
 *
 * ⚠️  HISTORICAL BUG — DO NOT REPEAT:  The IDA pseudo for this function uses
 * signed-decimal case labels (e.g. `v5 == -1784579468`) because the original
 * MSVC compiler emitted them as INT32 immediates.  Earlier port converted
 * those decimals to hex MENTALLY and got several wrong, e.g.:
 *
 *     -1784579468  →  0x95A17A74  (correct, from asm `cmp edx, 95A17A74h`)
 *                  →  0x94ACF0B4  (WRONG — what the old port had)
 *
 * That single mis-conversion caused the case to never match, leaving v7
 * unchanged, which made v5 ^= v7 toggle between two states forever.  The
 * symptom was a 200-iter "no case found" infinite loop in decrypt_trace.log.
 *
 * Other case-IDs that were mis-converted the same way (kept here as the
 * canonical list — never trust mental hex conversion of decimals):
 *
 *      decimal           wrong hex        correct hex
 *      ──────────────    ──────────       ──────────
 *      -1784579468       0x94ACF0B4       0x95A17A74
 *      -1898079277       0x8E4BCD13       0x8EDD9BD3
 *      -1993136731       0x7897C925       0x893325A5
 *       1947974556       0x7416EF9C       0x741BBB9C
 *       1268242258       0x4B978A52       0x4B97D752
 *       1309105459       0x4E07AE73       0x4E075D33
 *       1777307049       0x69EA47A9       0x69EF8DA9
 *       -280502203       0xEF496565       0xEF47E045
 *       -251496342       0xF0EDAC5A       0xF102786A
 *       -116360552       0xF90F7158       0xF9107A98
 *       1449317815       0x566D7CB7       0x5662D5B7   (terminator!)
 *
 * RULE: when porting, copy hex literals directly from the asm view (`cmp
 * edx, XXXXh`) or use a calculator.  NEVER convert decimal↔hex by hand.    */
static UINT64 ESP_DecryptPtr_Core(UINT64 raw, UINT32 k1, UINT32 k2, UINT32 k3)
{
    UINT64 v1 = (UINT64)((UINT32)raw ^ k1)
              | (((UINT64)((UINT32)(raw >> 32) ^ k2)) << 32);
    if (!v1) return 0;

    /* v8 init: ROR64(sign_ext(int32(k3)), 12) & 0xF */
    UINT64 v8 = _esp_ror64((UINT64)(INT64)(INT32)k3, 12) & 0xFu;
    UINT32 v5 = 0x6AE7FBEBu;
    UINT32 v7 = 0x7F9BAF67u;
    BOOL   early = FALSE;

    int guard = 0;
    while (v5 != 0x5662D5B7u) {
        if (++guard > 4096) return 0;

        BOOL set_v8_lo = FALSE;
        switch (v5) {
            case 0x6AE7FBEBu: v7 = 0x876311EEu; set_v8_lo = TRUE; break;
            case 0x365D069Au: v1 ^= v8; v7 = 0x07480AEAu; break;
            case 0x135F573Au: v8 ^= 0xAD81FFF8u; v1 = _esp_rol64(v1,32); v7 = 0x74C63B11u; break;
            case 0x05A68EACu: v8 ^= 0x07599584u; v7 = 0xEDD1CC2Eu; break;
            case 0x0A3C3784u: v1 = _esp_ror64(v1,32) ^ v8; v7 = 0x84E1AC57u; break;
            case 0x0B9A39A3u: v8 ^= 0x0520499Fu; v1 = _esp_ror64(v1,32); v7 = 0x054B9DB1u; break;
            case 0x13B761C1u: v8 ^= 0x3857867Fu; v7 = 0x5DB03CF2u; break;
            case 0x183F26EFu: v1 ^= v8; v7 = 0xF778C6AAu; break;
            case 0x31150C70u: {
                UINT64 o = v1;
                v1 = _esp_rol64(o, 32) ^ (UINT64)((UINT32)o ^ 0x5C7AB0E6u);
                v7 = 0x96D92C83u; set_v8_lo = TRUE;
                break;
            }
            case 0x434C8E58u: v1 ^= v8; v7 = 0x04543712u; break;
            case 0x4718B94Au: v1 = _esp_rol64(v1,32); early = TRUE; break;
            case 0x4830035Bu: v1 = _esp_rol64(v1,32); v7 = 0xB9327B31u; break;
            case 0x49BF5619u: v8 ^= 0x00479EF5u; v1 = _esp_ror64(v1,32); v7 = 0x42143ACFu; break;
            case 0x4B97D752u: v7 = 0x864FAA54u; set_v8_lo = TRUE; break;
            case 0x4E075D33u: v1 = _esp_ror64(v1,32); v7 = 0x0D4BD36Bu; break;
            case 0x69EF8DA9u: v1 = _esp_rol64(v1,32); v7 = 0x5FB28B33u; break;
            case 0x741BBB9Cu: v8 = (UINT64)((UINT32)v1 ^ 0x669F174Bu); v7 = 0xFF3DE5D5u; break;
            case 0x893325A5u: v1 ^= v8; v7 = 0x3FCB7CFFu; set_v8_lo = TRUE; break;
            case 0x8EDD9BD3u: v8 = (UINT64)((UINT32)v1 ^ 0x097DFB4Au); v7 = 0xC6ED9888u; break;
            case 0x95A17A74u: v1 = _esp_rol64(v1,32); v7 = 0x8D9E5C9Bu; break;
            case 0xA7CC20F3u: v8 ^= 0x0BB569BCu; v7 = 0xADF01777u; break;
            case 0xA9385526u: v8 = (UINT64)((UINT32)v1 ^ 0x3FE0348Fu); v7 = 0x0B665F15u; break;
            case 0xB457BF21u: v1 ^= v8; v7 = 0xFFC06873u; break;
            case 0xB6F8595Au: v8 ^= 0x046EE364u; v1 = _esp_rol64(v1,32); v7 = 0x02AFE67Bu; break;
            case 0xB8E1B51Du: v8 = (UINT64)((UINT32)v1 ^ 0x8A7CC1D2u); v1 = _esp_ror64(v1,32); v7 = 0x74583260u; break;
            case 0xCDD87D06u: v8 ^= 0x772FD793u; v7 = 0xA437F0AFu; break;
            case 0xD1C42575u: v8 = (UINT64)((UINT32)v1 ^ 0x0696AAB0u); v1 = _esp_rol64(v1,32); v7 = 0xBBD4BEEBu; break;
            case 0xE8774282u: v1 = _esp_rol64(v1,32); v7 = 0x61446727u; break;
            case 0xED84EA05u: v8 ^= 0x086D5EE4u; v7 = 0x78259071u; break;
            case 0xEF47E045u: v7 = 0xEAE16EE9u; set_v8_lo = TRUE; break;
            case 0xF102786Au: v1 ^= v8; v7 = 0xE2B519ABu; set_v8_lo = TRUE; break;
            case 0xF9107A98u: v8 ^= 0x04AE7CAAu; v1 = _esp_rol64(v1,32); v7 = 0xE7373BD4u; break;
            default: return 0;  /* unknown state → fail */
        }
        if (early) break;
        if (set_v8_lo) v8 = (UINT64)(UINT32)v1;
        v5 ^= v7;
    }
    return v1;
}

/* ── PointerManager::Decrypt ─────────────────────────────────────────────── *
 * Reads encrypted qword at enc_field_va via BYOVD then runs the state machine.
 * Uses keys 1, 2, 3.  key4 is only for float decryption.
 * ─────────────────────────────────────────────────────────────────────────── */
UINT64 ESP_DecryptPtr(UINT64 cr3, UINT64 enc_field_va)
{
    if (!enc_field_va || !g_EspState.keys_valid) return 0;

    UINT64 raw = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, enc_field_va, &raw, 8);
    BYOVD_UNLOCK();
    if (!ok || !raw) return 0;

    return ESP_DecryptPtr_Core(raw,
                               g_EspState.key1,
                               g_EspState.key2,
                               g_EspState.key3);
}

/* ── Esp_GetKeyFromFunction ──────────────────────────────────────────────── *
 * Scans up to 200 instructions in key initialization stub for mov/xor pairs.
 * ─────────────────────────────────────────────────────────────────────────── */
static UINT32 Esp_GetKeyFromFunction(UINT64 cr3, UINT64 function)
{
    if (!cr3 || !function) return 0;

    for (int step = 0; step < 200; ++step) {
        UINT8 op1 = 0, op2 = 0;
        BYOVD_LOCK();
        BOOL ok = BYOVD_ReadVA(cr3, function, &op1, 1) && BYOVD_ReadVA(cr3, function + 1, &op2, 1);
        BYOVD_UNLOCK();
        if (!ok) break;

        /* jmp rel32 (E9 xx xx xx xx) */
        if (op1 == 0xE9) {
            INT32 relOffset = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, function + 1, &relOffset, 4);
            BYOVD_UNLOCK();
            function = function + 5 + (INT64)relOffset;
            continue;
        }

        /* jmp rel8 (EB xx) */
        if (op1 == 0xEB) {
            INT8 relOffset = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, function + 1, &relOffset, 1);
            BYOVD_UNLOCK();
            function = function + 2 + (INT64)relOffset;
            continue;
        }

        /* mov eax, [rip+disp32] (8B 05 disp32) */
        if (op1 == 0x8B && op2 == 0x05) {
            UINT64 afterMov = function + 6;
            UINT8 nextOp1 = 0, nextOp2 = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, afterMov, &nextOp1, 1);
            BYOVD_ReadVA(cr3, afterMov + 1, &nextOp2, 1);
            BYOVD_UNLOCK();

            /* xor eax, [rip+disp32] (33 05 disp32) */
            if (nextOp1 == 0x33 && nextOp2 == 0x05) {
                INT32 disp1 = 0, disp2 = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, function + 2, &disp1, 4);
                BYOVD_ReadVA(cr3, afterMov + 2, &disp2, 4);
                BYOVD_UNLOCK();

                UINT64 key1_va = function + 6 + (INT64)disp1;
                UINT64 key2_va = afterMov + 6 + (INT64)disp2;

                UINT32 val1 = 0, val2 = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, key1_va, &val1, 4);
                BYOVD_ReadVA(cr3, key2_va, &val2, 4);
                BYOVD_UNLOCK();

                return val1 ^ val2;
            }

            /* jmp rel32 between mov and xor (E9 disp32) */
            if (nextOp1 == 0xE9) {
                INT32 jmpOffset = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, afterMov + 1, &jmpOffset, 4);
                BYOVD_UNLOCK();
                UINT64 jmpTarget = afterMov + 5 + (INT64)jmpOffset;

                UINT8 targetOp1 = 0, targetOp2 = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, jmpTarget, &targetOp1, 1);
                BYOVD_ReadVA(cr3, jmpTarget + 1, &targetOp2, 1);
                BYOVD_UNLOCK();

                if (targetOp1 == 0x33 && targetOp2 == 0x05) {
                    INT32 disp1 = 0, disp2 = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA(cr3, function + 2, &disp1, 4);
                    BYOVD_ReadVA(cr3, jmpTarget + 2, &disp2, 4);
                    BYOVD_UNLOCK();

                    UINT64 key1_va = function + 6 + (INT64)disp1;
                    UINT64 key2_va = jmpTarget + 6 + (INT64)disp2;

                    UINT32 val1 = 0, val2 = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA(cr3, key1_va, &val1, 4);
                    BYOVD_ReadVA(cr3, key2_va, &val2, 4);
                    BYOVD_UNLOCK();

                    return val1 ^ val2;
                }
            }
        }

        function += 1;
    }

    return 0;
}

/* Esp_ParseKeyStub replaced with dynamic Esp_GetKeyFromFunction AOB parser. */

/* ── Esp_TraceDecrypt ────────────────────────────────────────────────────── *
 * Faithful port of sub_7FF66F80EF10 state machine — verified 1:1 against
 * disassembly.  Reads encrypted qword at encVA, runs the decryptor, and logs
 * each iteration to decrypt_trace.log.  All 32 cases use a flat switch with
 * constants copied byte-for-byte from the asm (no hex/decimal conversions). */
void Esp_TraceDecrypt(UINT64 cr3, UINT64 encVA,
                      UINT32 k1, UINT32 k2, UINT32 k3, UINT32 k4)
{
    DEBUG_TRACE("ENTER cr3=0x%I64X encVA=0x%I64X", cr3, encVA);
    UINT64 raw = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, encVA, &raw, 8);
    BYOVD_UNLOCK();

    DEBUG_TRACE("=== START encVA=0x%I64X raw=0x%016I64X read_ok=%d ===", encVA, raw, ok);
    DEBUG_TRACE("keys: k1=0x%08X k2=0x%08X k3=0x%08X k4=0x%08X", k1, k2, k3, k4);
    if (!ok || !raw) { DEBUG_TRACE("abort: no raw"); return; }

    UINT64 v1 = (UINT64)((UINT32)raw ^ k1)
              | (((UINT64)((UINT32)(raw >> 32) ^ k2)) << 32);
    DEBUG_TRACE("post-init xor: v1=0x%016I64X", v1);
    if (!v1) { DEBUG_TRACE("abort: v1=0"); return; }

    UINT64 v8 = _esp_ror64((UINT64)(INT64)(INT32)k3, 12) & 0xFu;
    UINT32 v5 = 0x6AE7FBEBu;
    UINT32 v7 = 0x7F9BAF67u;

    DEBUG_TRACE("init: v5=0x%08X v7=0x%08X v8=0x%016I64X", v5, v7, v8);

    int  iter = 0;
    BOOL terminated = FALSE, early_exit = FALSE;

    while (iter < 256) {
        DEBUG_TRACE("[%03d] v5=0x%08X v7=0x%08X v8=0x%016I64X v1=0x%016I64X",
                    iter, v5, v7, v8, v1);

        BOOL set_v8_lo = FALSE;
        BOOL bad_case  = FALSE;
        switch (v5) {
            case 0x6AE7FBEBu: v7 = 0x876311EEu; set_v8_lo = TRUE; break;
            case 0x365D069Au: v1 ^= v8; v7 = 0x07480AEAu; break;
            case 0x135F573Au: v8 ^= 0xAD81FFF8u; v1 = _esp_rol64(v1,32); v7 = 0x74C63B11u; break;
            case 0x05A68EACu: v8 ^= 0x07599584u; v7 = 0xEDD1CC2Eu; break;
            case 0x0A3C3784u: v1 = _esp_ror64(v1,32) ^ v8; v7 = 0x84E1AC57u; break;
            case 0x0B9A39A3u: v8 ^= 0x0520499Fu; v1 = _esp_ror64(v1,32); v7 = 0x054B9DB1u; break;
            case 0x13B761C1u: v8 ^= 0x3857867Fu; v7 = 0x5DB03CF2u; break;
            case 0x183F26EFu: v1 ^= v8; v7 = 0xF778C6AAu; break;
            case 0x31150C70u: {
                UINT64 o = v1;
                v1 = _esp_rol64(o, 32) ^ (UINT64)((UINT32)o ^ 0x5C7AB0E6u);
                v7 = 0x96D92C83u; set_v8_lo = TRUE;
                break;
            }
            case 0x434C8E58u: v1 ^= v8; v7 = 0x04543712u; break;
            case 0x4718B94Au:
                v1 = _esp_rol64(v1,32);
                early_exit = TRUE;
                DEBUG_TRACE("  -> case 0x4718B94A: early_exit (LABEL_78)");
                goto LBL_DONE;
            case 0x4830035Bu: v1 = _esp_rol64(v1,32); v7 = 0xB9327B31u; break;
            case 0x49BF5619u: v8 ^= 0x00479EF5u; v1 = _esp_ror64(v1,32); v7 = 0x42143ACFu; break;
            case 0x4B97D752u: v7 = 0x864FAA54u; set_v8_lo = TRUE; break;
            case 0x4E075D33u: v1 = _esp_ror64(v1,32); v7 = 0x0D4BD36Bu; break;
            case 0x69EF8DA9u: v1 = _esp_rol64(v1,32); v7 = 0x5FB28B33u; break;
            case 0x741BBB9Cu: v8 = (UINT64)((UINT32)v1 ^ 0x669F174Bu); v7 = 0xFF3DE5D5u; break;
            case 0x893325A5u: v1 ^= v8; v7 = 0x3FCB7CFFu; set_v8_lo = TRUE; break;
            case 0x8EDD9BD3u: v8 = (UINT64)((UINT32)v1 ^ 0x097DFB4Au); v7 = 0xC6ED9888u; break;
            case 0x95A17A74u: v1 = _esp_rol64(v1,32); v7 = 0x8D9E5C9Bu; break;
            case 0xA7CC20F3u: v8 ^= 0x0BB569BCu; v7 = 0xADF01777u; break;
            case 0xA9385526u: v8 = (UINT64)((UINT32)v1 ^ 0x3FE0348Fu); v7 = 0x0B665F15u; break;
            case 0xB457BF21u: v1 ^= v8; v7 = 0xFFC06873u; break;
            case 0xB6F8595Au: v8 ^= 0x046EE364u; v1 = _esp_rol64(v1,32); v7 = 0x02AFE67Bu; break;
            case 0xB8E1B51Du: v8 = (UINT64)((UINT32)v1 ^ 0x8A7CC1D2u); v1 = _esp_ror64(v1,32); v7 = 0x74583260u; break;
            case 0xCDD87D06u: v8 ^= 0x772FD793u; v7 = 0xA437F0AFu; break;
            case 0xD1C42575u: v8 = (UINT64)((UINT32)v1 ^ 0x0696AAB0u); v1 = _esp_rol64(v1,32); v7 = 0xBBD4BEEBu; break;
            case 0xE8774282u: v1 = _esp_rol64(v1,32); v7 = 0x61446727u; break;
            case 0xED84EA05u: v8 ^= 0x086D5EE4u; v7 = 0x78259071u; break;
            case 0xEF47E045u: v7 = 0xEAE16EE9u; set_v8_lo = TRUE; break;
            case 0xF102786Au: v1 ^= v8; v7 = 0xE2B519ABu; set_v8_lo = TRUE; break;
            case 0xF9107A98u: v8 ^= 0x04AE7CAAu; v1 = _esp_rol64(v1,32); v7 = 0xE7373BD4u; break;
            default:
                DEBUG_TRACE("  ! UNKNOWN CASE v5=0x%08X — bailing", v5);
                bad_case = TRUE;
                break;
        }
        if (bad_case) break;
        if (set_v8_lo) {
            v8 = (UINT64)(UINT32)v1;
            DEBUG_TRACE("  -> LBL_74: v8 := (uint32)v1 = 0x%I64X", v8);
        }
        v5 ^= v7;
        if (v5 == 0x5662D5B7u) { terminated = TRUE; break; }
        iter++;
    }

LBL_DONE:
    DEBUG_TRACE("=== END iters=%d v5=0x%08X v1=0x%016I64X term=%d early=%d ===",
                iter, v5, v1, terminated, early_exit);

    /* Sanity check: decrypted ptr should be a typical user-space VA */
    if (terminated || early_exit) {
        DEBUG_TRACE("decrypted ptr looks %s (high32=0x%08X)",
                    ((v1 >> 32) >= 0x7FF00000ull && (v1 >> 32) <= 0x7FFFFFFFull)
                        ? "PLAUSIBLE" : "BOGUS",
                    (UINT32)(v1 >> 32));
    }
}

/* ── W2S: ESP_ResolveMatrices ─────────────────────────────────────────────── *
 * Scan ESP_AOB_W2S anchor in .text, decode the `lea rdx,[rip+disp32]` at
 * match+0, then compute viewMatrix VA = decoded + 0, projMatrix = decoded + 0x40.
 *
 * Defensive: verifies the lea opcode bytes (48 8D 15) before trusting disp32.
 * Idempotent: returns immediately if matrices_valid is already set.          */
BOOL ESP_ResolveMatrices(void)
{
    if (g_EspState.matrices_valid && g_EspState.view_mat_va) return TRUE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2base = GetDestiny2Base();
    if (!cr3 || !d2base) return FALSE;

    /* Build masked pattern from ESP_AOB_W2S / ESP_MASK_W2S strings. */
    UINT8 pat[ESP_AOB_W2S_LEN];
    UINT8 msk[ESP_AOB_W2S_LEN];
    {
        const char *p = ESP_AOB_W2S;
        const char *m = ESP_MASK_W2S;
        for (int i = 0; i < ESP_AOB_W2S_LEN; i++) {
            pat[i] = (UINT8)p[i];
            msk[i] = (m[i] == 'x') ? 0xFFu : 0x00u;
        }
    }

    /* The W2S AOB is a generic epilogue (`E9 ?? ?? ?? ?? 48 83 C4 28 C3 …`)
     * and matches in many non-relevant places.  We must therefore scan ALL
     * occurrences in .text and validate +0x19 contains the expected
     * `48 8D 0D ?? ?? ?? ??` (lea rcx, [rip+disp32]) opcode.  Pick the first
     * match that satisfies the discriminator AND whose resolved `cam_addr`
     * falls within the module image (sane .data target, not a wild ptr).
     *
     * Retry cooldown: when no candidate validates we still get called every
     * frame from the render thread.  Throttle the full sweep to once every
     * 2 s so the log doesn't fill with "lea bytes mismatch". */
    static DWORD s_lastTryMs = 0;
    DWORD nowMs = GetTickCount();
    if (s_lastTryMs && (nowMs - s_lastTryMs) < 2000) return FALSE;
    s_lastTryMs = nowMs;

    UINT32 d2Tds = 0;
    {
        LONG e_lfanew = 0;
        BYOVD_LOCK();
        BOOL okTds = BYOVD_ReadVA(cr3, d2base + 0x3C, &e_lfanew, 4);
        if (okTds && e_lfanew > 0 && e_lfanew < 0x1000) {
            BYOVD_ReadVA(cr3, d2base + (UINT32)e_lfanew + 8, &d2Tds, 4);
        }
        BYOVD_UNLOCK();
    }

    UINT64 textVA = 0, textLen = 0;
    if (!BYOVD_GetTextBounds(cr3, d2base, &textVA, &textLen) ||
        !textVA || !textLen) {
        DEBUG_ESP("W2S: GetTextBounds failed (textVA=%I64X len=%I64X)", textVA, textLen);
        return FALSE;
    }

    /* Local player position used to score candidates: the gameplay camera's
     * r3 (cam_pos) lives within ~5m of the local player in 3P (~0m in 1P).
     * Other camera structs (HUD/photo/director) are 10+ m away. */
    float lpPos[3] = {0.0f, 0.0f, 0.0f};
    BOOL  hasLP = FALSE;
    if (Skeleton_GetCachedLPRootPos(lpPos)) {
        hasLP = TRUE;
    } else {
        hasLP = TigerList_ReadLPPosition(lpPos);
    }
    float lpx = lpPos[0];
    float lpy = lpPos[1];
    float lpz = lpPos[2];

    int    candCount   = 0;
    int    leaRejected = 0;
    int    rangeRejected = 0;
    UINT64 first_match = 0;
    UINT64 first_valid = 0;       /* first lea+range-ok candidate (fallback) */
    UINT64 best_cam    = 0;       /* candidate closest to local player       */
    float  best_dist   = 1e30f;
    UINT64 cur         = textVA;
    UINT64 textEnd     = textVA + textLen;
    UINT64 imgEnd      = d2base + 0x10000000ULL;  /* 256 MB cap, way beyond D2 .data */

    while (cur + ESP_AOB_W2S_LEN < textEnd) {
        UINT64 remain = textEnd - cur;
        BYOVD_LOCK();
        UINT64 m = BYOVD_ScanPatternRaw(cr3, cur, remain, pat, msk, ESP_AOB_W2S_LEN);
        BYOVD_UNLOCK();
        if (!m) break;
        if (!first_match) first_match = m;
        candCount++;

        if (m < cur || m + ESP_AOB_W2S_LEN > textEnd) break;

        UINT8 lea[ESP_W2S_LEA_SIZE] = {0};
        BYOVD_LOCK();
        BOOL rok = BYOVD_ReadVA_NoCache(cr3, m + ESP_W2S_LEA_OFFSET, lea, ESP_W2S_LEA_SIZE);
        BYOVD_UNLOCK();

        DEBUG_ESP("W2S RAW #%d match=0x%I64X lea=%02X %02X %02X %02X %02X %02X %02X rok=%d",
                  candCount, m, lea[0], lea[1], lea[2], lea[3], lea[4], lea[5], lea[6], rok);
        /* Validate: expect `lea rdx,[rip+disp32]` = 48 8D 15 ?? ?? ?? ?? */
        if (rok && lea[0] == 0x48 && lea[1] == 0x8D && lea[2] == 0x15) {
            INT32 disp = (INT32)((UINT32)lea[3]        |
                                 ((UINT32)lea[4] <<  8)|
                                 ((UINT32)lea[5] << 16)|
                                 ((UINT32)lea[6] << 24));
            UINT64 lea_va = m + ESP_W2S_LEA_OFFSET;
            UINT64 ca     = lea_va + ESP_W2S_LEA_SIZE + (INT64)disp;
            if (ca >= d2base && ca < imgEnd) {
                float view_peek[16] = {0};
                float proj_peek[16] = {0};
                BYOVD_LOCK();
                BYOVD_ReadVA_NoCache(cr3, ca + ESP_W2S_OFF_VIEW, view_peek, 64);
                BYOVD_ReadVA_NoCache(cr3, ca + ESP_W2S_OFF_PROJ, proj_peek, 64);
                BYOVD_UNLOCK();

                /* Discard obvious garbage: a real camera struct has
                 * orthonormal-ish basis vectors and a finite r3.w == 1. */
                BOOL sane = (view_peek[15] > 0.5f && view_peek[15] < 1.5f) &&
                            (proj_peek[0] > 0.1f && proj_peek[0] < 5.0f) &&
                            (proj_peek[5] > 0.1f && proj_peek[5] < 5.0f);

                /* Score by |eye(LP)|: transform LP through this candidate's
                 * view matrix.  For the gameplay camera, LP sits at the eye
                 * origin (FP) or within ~5m forward of it (3P), so a small
                 * magnitude here uniquely fingerprints the right struct.
                 * Wrong cameras (shadow/director/photo) yield 100m+.       */
                float dlp = -1.0f;
                if (sane && hasLP) {
                    float ex = view_peek[0]*lpx + view_peek[4]*lpy + view_peek[ 8]*lpz + view_peek[12];
                    float ey = view_peek[1]*lpx + view_peek[5]*lpy + view_peek[ 9]*lpz + view_peek[13];
                    float ez = view_peek[2]*lpx + view_peek[6]*lpy + view_peek[10]*lpz + view_peek[14];
                    dlp = sqrtf(ex*ex + ey*ey + ez*ez);
                }

                DEBUG_ESP("W2S CAND #%d ca=0x%I64X r3=(%.2f,%.2f,%.2f,%.2f) proj=(%.3f,%.3f) sane=%d dlp=%.2f",
                          candCount, ca,
                          view_peek[12], view_peek[13], view_peek[14], view_peek[15],
                          proj_peek[0], proj_peek[5], sane, dlp);

                if (sane) {
                    if (!first_valid) first_valid = ca;
                    if (hasLP && dlp >= 0.0f && dlp < best_dist) {
                        best_dist = dlp;
                        best_cam  = ca;
                    }
                }
            } else {
                rangeRejected++;
            }
        } else {
            leaRejected++;
        }

        cur = m + 1;
    }

    BOOL flyActive = Fly_IsEnabled() || FlyDir_IsEnabled();
    UINT64 cam_addr = 0;
    if (hasLP && flyActive) {
        /* Require closest cam to be within 12m (covers 1P=0m, 3P=3-5m, vehicle ~8m).
         * If best is farther, refuse to publish — caller will retry next frame
         * once Havok refreshes local_pos or the player moves. */
        if (best_cam && best_dist <= 50.0f) {
            cam_addr = best_cam;
        } else {
            DEBUG_ESP("W2S: best cand |eye(LP)|=%.2f > 50m threshold (cands=%d) — deferring",
                      best_dist, candCount);
            return FALSE;
        }
    } else {
        /* No LP yet: pick first sane candidate as a temporary best guess.
         * GetEntityBoxes will detect a stale pick (cam too far) and force
         * a re-scan once Havok publishes local_pos. */
        cam_addr = first_valid;
        if (!cam_addr) {
            DEBUG_ESP("W2S: no sane candidate (scanned=%d leaBad=%d rangeBad=%d firstMatch=0x%I64X)",
                      candCount, leaRejected, rangeRejected, first_match);
            return FALSE;
        }
    }

    g_EspState.view_mat_va    = cam_addr + ESP_W2S_OFF_VIEW;
    g_EspState.proj_mat_va    = cam_addr + ESP_W2S_OFF_PROJ;
    g_EspState.matrices_valid = TRUE;

    /* Persist the freshly-picked view_va to the on-disk AOB cache so a
     * stale value doesn't get reloaded next session. */
    {
        AobCacheRec rec;
        if (AobCache_Read(d2base, d2Tds, &rec)) {
            if (rec.view_mat_va != g_EspState.view_mat_va) {
                rec.view_mat_va = g_EspState.view_mat_va;
                AobCache_Write(d2base, d2Tds, &rec);
                DEBUG_ESP("W2S: cache updated view_va -> 0x%I64X", g_EspState.view_mat_va);
            }
        }
    }

    DEBUG_ESP("W2S: SUCCESS cam=0x%I64X view=0x%I64X proj=0x%I64X dlp=%.2f cands=%d",
              cam_addr, g_EspState.view_mat_va, g_EspState.proj_mat_va,
              hasLP ? best_dist : -1.0f, candCount);
    return TRUE;
}

/* ── W2S: ESP_ReadMatrices ────────────────────────────────────────────────── */
BOOL ESP_ReadMatrices(float view[16], float proj[16])
{
    if (!view || !proj) return FALSE;
    if (!g_EspState.matrices_valid || !g_EspState.view_mat_va) return FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    float matBuf[32];
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, g_EspState.view_mat_va, matBuf, 128);
    BYOVD_UNLOCK();
    if (ok) {
        /* Discard obvious garbage: a real camera struct has
         * orthonormal-ish basis vectors and a finite r3.w == 1. */
        BOOL sane = (matBuf[15] > 0.5f && matBuf[15] < 1.5f) &&
                    (matBuf[16] > 0.05f && matBuf[16] < 100.0f) &&
                    (matBuf[21] > 0.05f && matBuf[21] < 100.0f);
        if (!sane) return FALSE;

        memcpy(view, matBuf, 64);
        memcpy(proj, matBuf + 16, 64);
    }
    return ok;
}

/* ── W2S: ESP_WorldToScreen ───────────────────────────────────────────────── *
 * Treats both matrices as ROW-MAJOR (engine storage convention) and applies
 * them as (world_row · view) · proj — i.e. world point is a row vector
 * multiplied on the LEFT of view, then proj.  Accumulator math:
 *   v[i] = wx*view[0+i] + wy*view[4+i] + wz*view[8+i] + view[12+i]   (i=0..3)
 *   c[i] = v.x*proj[0+i] + v.y*proj[4+i] + v.z*proj[8+i] + v.w*proj[12+i]
 * Then perspective divide and viewport map (Y inverted).                     *
 * If the engine actually stores column-major / transposed matrices, this
 * function will produce mirrored or rotated output — easy to detect on a
 * known-good reference point and swap to (view·world) layout if needed.     */
BOOL ESP_WorldToScreen(const float view[16], const float proj[16],
                       float wx, float wy, float wz,
                       int screen_w, int screen_h,
                       float *out_x, float *out_y)
{
    if (!view || !proj || !out_x || !out_y || screen_w <= 0 || screen_h <= 0)
        return FALSE;

    /* Tiger Engine stores BOTH matrices as COLUMN-MAJOR:
     *   M[i,j] = mat[i + 4*j]
     * The view matrix is WORLD-TO-CAMERA (not camera-to-world).  Verified
     * against live data: cam_pos_world = -R^T * t lands within 1m of the
     * local player's Havok rb_coords.  The dumped "r3" floats
     * (view[12..15]) are the translation column t of W→C, NOT cam world
     * position.
     *
     * Column-major matrix×vector:
     *   eye.i = sum_j view[i + 4j] * world.j
     * with world treated as homogeneous (wx,wy,wz,1).                     */
    /* Vectorized SSE2 Column-major matrix×vector multiplication */
    __m128 v_wx = _mm_set1_ps(wx);
    __m128 v_wy = _mm_set1_ps(wy);
    __m128 v_wz = _mm_set1_ps(wz);

    __m128 v_col0 = _mm_loadu_ps(&view[0]);
    __m128 v_col1 = _mm_loadu_ps(&view[4]);
    __m128 v_col2 = _mm_loadu_ps(&view[8]);
    __m128 v_col3 = _mm_loadu_ps(&view[12]);

    __m128 v_eye = _mm_add_ps(_mm_add_ps(_mm_mul_ps(v_col0, v_wx), _mm_mul_ps(v_col1, v_wy)),
                             _mm_add_ps(_mm_mul_ps(v_col2, v_wz), v_col3));

    float eye_arr[4];
    _mm_storeu_ps(eye_arr, v_eye);
    float ex = eye_arr[0], ey = eye_arr[1], ez = eye_arr[2], ew = eye_arr[3];

    __m128 v_ex = _mm_set1_ps(ex);
    __m128 v_ey = _mm_set1_ps(ey);
    __m128 v_ez = _mm_set1_ps(ez);
    __m128 v_ew = _mm_set1_ps(ew);

    __m128 v_pcol0 = _mm_loadu_ps(&proj[0]);
    __m128 v_pcol1 = _mm_loadu_ps(&proj[4]);
    __m128 v_pcol2 = _mm_loadu_ps(&proj[8]);
    __m128 v_pcol3 = _mm_loadu_ps(&proj[12]);

    __m128 v_clip = _mm_add_ps(_mm_add_ps(_mm_mul_ps(v_pcol0, v_ex), _mm_mul_ps(v_pcol1, v_ey)),
                               _mm_add_ps(_mm_mul_ps(v_pcol2, v_ez), _mm_mul_ps(v_pcol3, v_ew)));

    float clip_arr[4];
    _mm_storeu_ps(clip_arr, v_clip);
    float cx = clip_arr[0], cy = clip_arr[1], cw = clip_arr[3];

    if (cw < 0.001f) return FALSE;   /* behind camera / near-plane          */

    float inv_w = 1.0f / cw;
    float ndc_x = cx * inv_w;        /* [-1,+1] left→right                  */
    float ndc_y = cy * inv_w;        /* [-1,+1] bottom→top                  */

    *out_x = ((ndc_x + 1.0f) * 0.5f) * (float)screen_w;
    *out_y = ((1.0f - ndc_y) * 0.5f) * (float)screen_h;
    return TRUE;
}

/* ── W2S: ESP_WorldToScreen_FOV ───────────────────────────────────────────── *
 * Faithful port of the UnknownCheats Destiny 2 W2S (FOV-based, single
 * matrix).  Treats the matrix as a CAMERA-WORLD transform:
 *   row 0 (m[0..3])   = right vector  (xyz; m[3] ignored)
 *   row 1 (m[4..7])   = up vector
 *   row 2 (m[8..11])  = forward vector (NEGATED for projection — engine
 *                                       convention is right-handed)
 *   row 3 (m[12..15]) = camera world position
 *
 * Algorithm:
 *   delta  = world - camera_pos
 *   x_proj = delta · right
 *   y_proj = delta · up
 *   z_proj = delta · (-forward)
 *   if z_proj < 0  → behind camera, fail
 *   screen.x = cx * (1 + x_proj / (FOV_TAN * z_proj))
 *   screen.y = cy * (1 - y_proj / (FOV_TAN * z_proj) * ASPECT)
 *
 * FOV is HARDCODED at ESP_DEFAULT_FOV_TAN (= tan(105°/2)).  The 16:9 aspect
 * ratio compensates for non-square pixel mapping on Y.                       */
BOOL ESP_WorldToScreen_FOV(const float view[16],
                           float wx, float wy, float wz,
                           int screen_w, int screen_h,
                           float *out_x, float *out_y)
{
    if (!view || !out_x || !out_y || screen_w <= 0 || screen_h <= 0)
        return FALSE;

    /* delta = world - camera_pos (row 3) */
    float dx = wx - view[12];
    float dy = wy - view[13];
    float dz = wz - view[14];

    /* Project onto camera basis vectors (rows 0,1,2). */
    float xp =  dx*view[0] + dy*view[1] + dz*view[ 2];     /* right    */
    float yp =  dx*view[4] + dy*view[5] + dz*view[ 6];     /* up       */
    float zp = -(dx*view[8] + dy*view[9] + dz*view[10]);   /* -forward */

    if (zp < 0.001f) return FALSE;   /* behind camera                  */

    float cx = (float)screen_w * 0.5f;
    float cy = (float)screen_h * 0.5f;
    float inv = 1.0f / (ESP_DEFAULT_FOV_TAN * zp);

    *out_x = cx * (1.0f + xp * inv);
    *out_y = cy * (1.0f - yp * inv * ESP_ASPECT_16_9);
    return TRUE;
}



/* ── ESP_GetEntityBoxes ──────────────────────────────────────────────────────
 * TigerList-driven player ESP using bone handles.
 *
 * Pipeline (per call):
 *   1. Resolve W2S matrices (lazy).
 *   2. Resolve the TigerList container via Fly_GetPObjDecryptedVA().
 *   3. Read container header (data ptr, stride, count).
 *   4. For each player entry:
 *        a) Read bone_array_handle @+0x4610 (confirmed offset).
 *        b) esp_datum_resolve(handle) → component pointer (via datum table).
 *        c) Walk component chain (+0x18 next) up to ESP_COMP_MAX_WALK hops
 *           until we hit one with bone_count @+0x140 > 0.
 *        d) Read bone[0] position (pelvis/root) from comp+0x180+0x10 — this
 *           is the plaintext world coord.
 *        e) Project head (bone[0] + BODY_HEIGHT up) and feet; build box.
 *
 * No Havok, no SObject pool, no cipher brute force.  Handle resolution
 * gives us plaintext world coords directly.                              */
int ESP_GetEntityBoxes(int screen_w, int screen_h, EspBox *out, int max_out)
{
    if (!out || max_out <= 0 || screen_w <= 0 || screen_h <= 0) return 0;

    DWORD bailNowMs = GetTickCount();

    if (!g_EspState.matrices_valid) {
        if (!ESP_ResolveMatrices() || !g_EspState.matrices_valid) return 0;
    }

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return 0;


    float view[16] = {0.0f};
    float proj[16] = {0.0f};
    if (!ESP_ReadMatrices(view, proj)) return 0;

    /* Camera world position: camPos = -R^T * t  (column-major world-to-camera).
     * R columns = view[0..2], view[4..6], view[8..10]; t = view[12..14].
     * Verified: result lands within 1m of Havok rb_coords when LP valid.     */
    float camX = -(view[0]*view[12] + view[1]*view[13] + view[2]*view[14]);
    float camY = -(view[4]*view[12] + view[5]*view[13] + view[6]*view[14]);
    float camZ = -(view[8]*view[12] + view[9]*view[13] + view[10]*view[14]);

    int written = 0;
    int nActiveTLEnemies = 0;
    /* SL indices confirmed by active TL slots — used to filter SL draw pass */
    UINT32 activeSLIdx[16] = {0};
    int    nActiveSLIdx    = 0;
    float lpPosX = 0.0f, lpPosY = 0.0f, lpPosZ = 0.0f;
    BOOL  lpPosValid = FALSE;
    {
        float lpPosCached[3] = {0.0f, 0.0f, 0.0f};
        if (Skeleton_GetCachedLPRootPos(lpPosCached)) {
            lpPosX = lpPosCached[0];
            lpPosY = lpPosCached[1];
            lpPosZ = lpPosCached[2];
            lpPosValid = TRUE;
        }
    }

    static DWORD s_lastDumpMs = 0;
    BOOL dumpThis = (DWORD)(bailNowMs - s_lastDumpMs) >= 2000;
    if (dumpThis) s_lastDumpMs = bailNowMs;

    /* ── TigerList ESP loop ──────────────────────────────────────────────────
     * Flow (matching fly.c Fly_ReadLocalCoordsTL):
     *   ESP_DecryptPtr(g_players_va) → container
     *   *(u64*)(container+0x00)      → arrPtr  (actual slot array)
     *   arrPtr + i*0x4F20            → slot_i
     *
     * LP detection: coords at slot+0x0440 are plaintext ONLY for the LP slot;
     *   all other slots have NaN/garbage there (confirmed in fly.c).
     * Bone access: slot+0x4688 — u32 bone array datum handle (confirmed).
     *   Logging tries BOTH so we can determine the correct path.               */
    {
        /* Gated by TL validity, but we skip keys_valid check here so that
         * Schindler's List box rendering can run independently even when
         * TigerList/Datum decryption is currently down or scanning. */
        if (!g_EspState.tl_valid) {
            if (dumpThis) WriteEspLog("[ESP] TL not ready — g_players AOB not found");
            return 0;
        }
        if (!g_EspState.keys_valid) {
            if (dumpThis) WriteEspLog("[ESP] keys not valid — cannot decrypt");
            return 0;
        }
        /* Step 1: decrypt g_players → container, then deref container+0 → arrPtr */
        static UINT64 s_tlContainer = 0;
        static UINT64 s_tlArrPtr    = 0;
        static DWORD  s_tlBaseMs    = 0;
        DWORD tlNow = GetTickCount();
        if (!s_tlArrPtr || (DWORD)(tlNow - s_tlBaseMs) >= 16) {
            s_tlBaseMs    = tlNow;
            s_tlContainer = ESP_DecryptPtr(cr3, g_EspState.g_players_va);
            s_tlArrPtr    = 0;
            if (s_tlContainer) {
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, s_tlContainer + 0x08, &s_tlArrPtr, 8);
                BYOVD_UNLOCK();
            }
            if (!s_espLogInit) {
                char _ti[128];
                wsprintfA(_ti, "[TL] gpVA=0x%I64X container=0x%I64X arrPtr=0x%I64X",
                    g_EspState.g_players_va, s_tlContainer, s_tlArrPtr);
                WriteEspLog(_ti);
            }
        }
        if (!s_tlContainer) {
            if (dumpThis) {
                char _err[192];
                wsprintfA(_err, "[TL] container=0 — decrypt failed. Keys: k1=0x%X k2=0x%X k3=0x%X gpVA=0x%I64X",
                          g_EspState.key1, g_EspState.key2, g_EspState.key3, g_EspState.g_players_va);
                WriteEspLog(_err);
            }
            goto skip_tl_loop;
        }
        if (!s_tlArrPtr || s_tlArrPtr < 0x10000ULL) {
            if (dumpThis) {
                char _ti[192];
                wsprintfA(_ti, "[TL] arrPtr invalid=0x%I64X (container=0x%I64X). Keys: k1=0x%X k2=0x%X k3=0x%X",
                          s_tlArrPtr, s_tlContainer, g_EspState.key1, g_EspState.key2, g_EspState.key3);
                WriteEspLog(_ti);
            }
            goto skip_tl_loop;
        }
        if (!s_espLogInit) {
            s_espLogInit = TRUE;
            char _ei[96];
            wsprintfA(_ei, "[ESP] TL arrPtr=0x%I64X", s_tlArrPtr);
            WriteEspLog(_ei);
        }

        /* Step 2: read SL buffer once before iterating slots.
         * Throttled to 50ms: player positions update at ~20Hz which is more
         * than enough for ESP box smoothness. Eliminates a 16KB BYOVD read
         * on every call when skeleton thread calls this at higher rate. */
        UINT64 slBaseForBoxes = ESP_GetSLListBase();
        static BYTE  s_slBuf[32 * 0x200u];
        static BOOL  s_slBufOk  = FALSE;
        static DWORD s_slBufMs  = 0;
        static UINT64 s_slBufBase = 0;
        BOOL slBufOk = FALSE;
        {
            DWORD _slNow = GetTickCount();
            BOOL  _stale = (slBaseForBoxes != s_slBufBase) ||
                           ((DWORD)(_slNow - s_slBufMs) >= 16);
            if (slBaseForBoxes > 0x10000ULL && _stale) {
                BYOVD_LOCK();
                s_slBufOk   = BYOVD_ReadVA_NoCache(cr3, slBaseForBoxes, s_slBuf, sizeof(s_slBuf));
                BYOVD_UNLOCK();
                s_slBufMs   = _slNow;
                s_slBufBase = slBaseForBoxes;
            }
            slBufOk = s_slBufOk;
        }

        /* Step 3: batch-read all slot headers to eliminate individual IOCTL calls */
        typedef struct {
            UINT32 eHdl;
            UINT32 lpMark;
            UINT32 boneHdl;
        } SlotHdr;
        SlotHdr hdrs[TL_MAX_SLOTS] = {0};

        typedef struct {
            BYTE range1[32];  /* 0x0004 .. 0x0024 */
            BYTE range2[140]; /* 0x48A0 .. 0x492C */
        } SlotBuffers;
        static SlotBuffers slotBufs[TL_MAX_SLOTS]; /* static to prevent stack size warning */
        memset(slotBufs, 0, sizeof(slotBufs));

        BYOVD_READ_BATCH_ENTRY batch[TL_MAX_SLOTS * 2];
        int bc = 0;
        for (int si = 0; si < TL_MAX_SLOTS; si++) {
            UINT64 sv = s_tlArrPtr + (UINT64)si * TL_STRIDE;
            batch[bc].va = sv + 0x0004u; batch[bc].buf = slotBufs[si].range1; batch[bc].size = 32;  bc++;
            batch[bc].va = sv + 0x48A0u; batch[bc].buf = slotBufs[si].range2; batch[bc].size = 140; bc++;
        }
        BYOVD_ReadBatch(cr3, batch, bc);

        for (int si = 0; si < TL_MAX_SLOTS; si++) {
            hdrs[si].eHdl    = *(UINT32*)(slotBufs[si].range1 + 0);
            hdrs[si].lpMark  = *(UINT32*)(slotBufs[si].range1 + 28);
            hdrs[si].boneHdl = *(UINT32*)(slotBufs[si].range2 + 0);
        }

        INT32 lpIdx = LP_GetLocalPlayerIndex();
        for (int si = 0; si < TL_MAX_SLOTS; si++) {
            UINT64 slot = s_tlArrPtr + (UINT64)si * TL_STRIDE;

            UINT32 eHdl   = hdrs[si].eHdl;
            UINT32 lpMark = hdrs[si].lpMark;

            /* LP filter — hide local player from ESP boxes */
            if (dumpThis) {
                char _ds[150];
                wsprintfA(_ds, "[ESP_DBG] Slot #%d: eHdl=0x%X lpMark=0x%X boneHdl=0x%X",
                          si, eHdl, lpMark, hdrs[si].boneHdl);
                WriteEspLog(_ds);
            }
            if (si == lpIdx || lpMark == TL_LP_MARKER || eHdl == 0xFFFFFFFFu) {
                continue;
            }

            /* Skip slots without a valid bone handle (fixes localplayer box and ghost entities) */
            if (!is_tiger_handle(hdrs[si].boneHdl)) continue;

            /* Empty slot: eHdl==0 (and not LP) → skip */
            if (eHdl == 0) continue;
            nActiveTLEnemies++;
            /* Record SL index for this active slot so the SL pass can filter by it.
             * eHdl lower 13 bits = SL array index (0..63 for the 64-entry SL). */
            if (nActiveSLIdx < 16) activeSLIdx[nActiveSLIdx++] = eHdl & 0x3Fu;

            /* --- Get world position: playerDef handle → datum → SL lookup --- */
            /* Same approach as skeleton.c Skeleton_ReadAll SL lookup path.     */
            float posE[3]; posE[0]=posE[1]=posE[2]=0.0f;
            BOOL  posEOk  = FALSE;

            UINT32 playerDefHdl = eHdl; /* Same as slot + 0x04u, already batched */

            UINT64 slPtr = 0;
            if (is_tiger_handle(playerDefHdl) && slBufOk && g_EspState.datum_valid) {
                slPtr = esp_datum_resolve_ext(cr3, playerDefHdl, dumpThis);
                if (slPtr >= 0x10000ULL) {
                    /* Walk SL buffer to find entry matching slPtr */
                    for (int _ei = 0; _ei < 32 && !posEOk; _ei++) {
                        UINT64 _entry = slBaseForBoxes + (UINT64)_ei * 0x200u;
                        if (slPtr < _entry || slPtr >= _entry + 0x200u) continue;
                        const BYTE *_s = s_slBuf + (UINT64)_ei * 0x200u;
                        UINT16 _team16 = *(UINT16*)(_s + 0x0C0u);
                        if (_team16 == 0xFF00u) break; /* LP slot */
                        float _ex = *(float*)(_s + 0x1A0u);
                        float _ey = *(float*)(_s + 0x1A4u);
                        float _ez = *(float*)(_s + 0x1A8u);
                        if (!(_ex==_ex) || !(_ey==_ey) || !(_ez==_ez)) break;
                        if (fabsf(_ex)+fabsf(_ey)+fabsf(_ez) < 0.5f) break;
                        posE[0]=_ex; posE[1]=_ey; posE[2]=_ez;
                        posEOk = TRUE;
                    }
                }
            }

            if (dumpThis && !posEOk) {
                char _dpe[200];
                wsprintfA(_dpe, "[ESP_DBG] Slot #%d position resolve failed: slPtr=0x%I64X slBufOk=%d datum_valid=%d",
                          si, slPtr, slBufOk, g_EspState.datum_valid);
                WriteEspLog(_dpe);
            }
            if (!posEOk) continue;
            float *pos = posE;

            /* Skip LP: compare against LP world position */
            if (lpPosValid) {
                float _lx=pos[0]-lpPosX, _ly=pos[1]-lpPosY, _lz=pos[2]-lpPosZ;
                if (_lx*_lx+_ly*_ly+_lz*_lz < 4.0f) continue;
            }

            float ddx=pos[0]-camX, ddy=pos[1]-camY, ddz=pos[2]-camZ;
            float dist2 = ddx*ddx+ddy*ddy+ddz*ddz;
            if (dist2 > 200.f*200.f) continue;

            /* Project head (+0.9m) and feet (−0.9m) for bone-based boxes */
            float sx=0,sy=0,fx=0,fy=0;
            if (!ESP_WorldToScreen(view,proj,pos[0],pos[1],pos[2]+0.9f,screen_w,screen_h,&sx,&sy)) continue;
            if (!ESP_WorldToScreen(view,proj,pos[0],pos[1],pos[2]-0.9f,screen_w,screen_h,&fx,&fy)) continue;
            float cx=(sx+fx)*0.5f, cy=(sy+fy)*0.5f;
            float boxH=fy-sy; if(boxH<8.f)boxH=8.f; if(boxH>600.f)boxH=600.f;
            if (cx < -300.f || cx > (float)screen_w+300.f) continue;
            if (cy < -300.f || cy > (float)screen_h+300.f) continue;

            if (written >= max_out) break;
            out[written].cx=cx; out[written].cy=cy;
            out[written].w=boxH*0.5f; out[written].h=boxH;
            out[written].dist=sqrtf(dist2);
            out[written].entity_ptr=slot;
            out[written].team=1;
            out[written].worldX=pos[0];
            out[written].worldY=pos[1];
            out[written].worldZ=pos[2];
            written++;
skip_tl_loop:;
        }
    }

    /* ── SL-based enemy position pass ────────────────────────────────────── *
     * Disable the fallback pass to draw boxes ONLY for valid skeletal entities. */
    goto skip_sl;
    static DWORD s_lastTLActiveMs = 0;
    if (nActiveTLEnemies > 0) s_lastTLActiveMs = GetTickCount();
    if (s_lastTLActiveMs == 0) goto skip_sl;
    if ((DWORD)(GetTickCount() - s_lastTLActiveMs) > 8000) goto skip_sl;
    /* If the TL pass already found boxes via find_skeleton, skip SL entirely.
     * SL is a fallback only — drawing both sources causes duplicate boxes. */
    if (written > 0) goto skip_sl;
    {
        UINT64 slBase = ESP_GetSLListBase();
        if (slBase > 0x10000ULL) {
            for (int ei = 0; ei < 64 && written < max_out; ei++) {
                /* Only draw SL entries confirmed by an active TL slot.
                 * This filters dead/invalid entities still present in SL. */
                if (nActiveSLIdx > 0) {
                    BOOL inTL = FALSE;
                    for (int k = 0; k < nActiveSLIdx; k++)
                        if (activeSLIdx[k] == (UINT32)ei) { inTL = TRUE; break; }
                    if (!inTL) continue;
                }
                UINT64 entryVA = slBase + 0x100ULL + (UINT64)ei * 0x80ULL;
                float pos[4] = {0};
                if (!BYOVD_ReadVA(cr3, entryVA + 0x20, pos, 16)) continue;
                float ex = pos[0];
                float ey = pos[1];
                float ez = pos[2];
                float ew = pos[3];

                /* Must be active (w==1.0) */
                if (fabsf(ew - 1.0f) > 0.01f) continue;
                /* Must have a real position */
                if (!(ex==ex) || !(ey==ey) || !(ez==ez)) continue;
                if (fabsf(ex)+fabsf(ey)+fabsf(ez) < 0.5f) continue;
                if (fabsf(ex)>1e5f||fabsf(ey)>1e5f||fabsf(ez)>1e5f) continue;

                /* Skip LP: compare against LP world position (slot+0x4920), not camera */
                if (lpPosValid) {
                    float lx=ex-lpPosX, ly=ey-lpPosY, lz=ez-lpPosZ;
                    if (lx*lx+ly*ly+lz*lz < 4.0f) continue;   /* < 2m → LP itself */
                }
                float ddx=ex-camX, ddy=ey-camY, ddz=ez-camZ;
                float dist2 = ddx*ddx+ddy*ddy+ddz*ddz;
                if (dist2 > 200.f*200.f) continue;

                if (dumpThis) {
                    char _sl[128];
                    wsprintfA(_sl,"[SL_POS] ei=%d pos=(%d,%d,%d) dist=%d",
                        ei,(int)ex,(int)ey,(int)ez,(int)sqrtf(dist2));
                    WriteEspLog(_sl);
                }

                /* Project head (+0.9m) and feet (−0.9m) */
                float sx=0,sy=0,fx=0,fy=0;
                if (!ESP_WorldToScreen(view,proj,ex,ey,ez+0.9f,screen_w,screen_h,&sx,&sy)) continue;
                if (!ESP_WorldToScreen(view,proj,ex,ey,ez-0.9f,screen_w,screen_h,&fx,&fy)) continue;
                float cx=(sx+fx)*0.5f, cy=(sy+fy)*0.5f;
                float boxH=fy-sy; if(boxH<8.f)boxH=8.f; if(boxH>600.f)boxH=600.f;
                /* Viewport cull: skip if center is far off-screen */
                if (cx < -300.f || cx > (float)screen_w+300.f) continue;
                if (cy < -300.f || cy > (float)screen_h+300.f) continue;

                out[written].cx=cx; out[written].cy=cy;
                out[written].w=boxH*0.5f; out[written].h=boxH;
                out[written].dist=sqrtf(dist2);
                out[written].entity_ptr=entryVA;
                out[written].team=1; /* enemy: passed LP filter */
                written++;
            }
        }
    }
skip_sl:;

    if (dumpThis) {
        s_lastDumpMs = bailNowMs;
        DEBUG_ESP("GetEntityBoxes: drawn=%d cam=(%.1f,%.1f,%.1f)", written, camX, camY, camZ);
    }
    return written;
}

/* ── ESP_Init ────────────────────────────────────────────────────────────── */
BOOL ESP_Init(void)
{
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2base = GetDestiny2Base();
    if (!cr3 || !d2base) return FALSE;

    UINT32 d2Tds = 0;
    {
        LONG e_lfanew = 0;
        BYOVD_LOCK();
        BOOL okTds = BYOVD_ReadVA(cr3, d2base + 0x3C, &e_lfanew, 4);
        if (okTds && e_lfanew > 0 && e_lfanew < 0x1000) {
            BYOVD_ReadVA(cr3, d2base + (UINT32)e_lfanew + 8, &d2Tds, 4);
        }
        BYOVD_UNLOCK();
    }

    /* Persistent cache across attach/detach AND loader restarts.
     * Stored at %TEMP%\<machine-hash>.tmp — see AobCache_GetPath in aob_cache.h.
     * Filename is derived per-machine (FNV-1a of volume serial + computer name)
     * so it has no static fingerprint. On full hit, ALL scans are skipped.   */
    static UINT64 s_cachedBase = 0;
    static UINT64 s_cached_datum_va = 0;
    static UINT64 s_cached_view_va  = 0;
    static BOOL   s_keysCached = FALSE;
    static BOOL   s_datumValidated = FALSE;
    BOOL datum_validated_local = FALSE;  /* set by datum scan; gates persistence */

    /* Disk cache load (one-shot per loader run). Purge stale keys on disk. */
    static BOOL s_diskLoaded = FALSE;
    if (!s_diskLoaded) {
        s_diskLoaded = TRUE;
        AobCacheRec rec;
        if (AobCache_Read(d2base, d2Tds, &rec)) {
            s_cachedBase = rec.d2base;
            s_cached_datum_va = rec.datum_va;
            s_cached_view_va  = rec.view_mat_va;
            s_keysCached = (s_cached_datum_va || s_cached_view_va);
            DEBUG_ESP("ESP_Init: loaded disk cache base=%I64X (keys purged) datum=%I64X view=%I64X",
                      s_cachedBase, s_cached_datum_va, s_cached_view_va);
        }
    }


    if (s_keysCached && s_cachedBase == d2base) {
        if (s_cached_view_va >= 0x10000ULL) {
            /* Sanity: with ESP_W2S_OFF_VIEW=0 the viewMatrix VA is 64-byte aligned.
             * The old AOB used OFF_VIEW=0x288, producing VAs with that alignment.
             * Discard any cached VA that is NOT 16-byte aligned (matrices must be). */
            if ((s_cached_view_va & 0xFu) == 0) {
                g_EspState.view_mat_va    = s_cached_view_va;
                g_EspState.proj_mat_va    = s_cached_view_va + ESP_W2S_OFF_PROJ;
                g_EspState.matrices_valid = 1;
            } else {
                DEBUG_ESP("ESP_Init: discarding misaligned cached view_va=0x%I64X (stale AOB)", s_cached_view_va);
                s_cached_view_va = 0;
            }
        }
        DEBUG_ESP("ESP_Init: cache hit keys=%d datum=%d view=%d",
                  g_EspState.keys_valid, g_EspState.datum_valid, g_EspState.matrices_valid);
    }

    /* W2S matrix anchor — runs BEFORE the fast-path return so a partial cache
     * (keys+datum hit, view miss) still gets the W2S scan to fill it in. */
    if (!g_EspState.matrices_valid) {
        ESP_ResolveMatrices();
    }

    /* TigerList anchor — runs BEFORE the fast-path return so a cache hit still
     * populates g_players_va / tl_valid on every attach.                      */
    if (!g_EspState.tl_valid) {
        BYOVD_LOCK();
        UINT64 gp_pre_instr = BYOVD_ScanPatternText(cr3, d2base,
                                                    gp_pre_pat, gp_pre_mask, 10);
        BYOVD_UNLOCK();
        if (gp_pre_instr) {
            INT32 gp_pre_disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, gp_pre_instr + 3, &gp_pre_disp, 4);
            BYOVD_UNLOCK();
            g_EspState.g_players_va = gp_pre_instr + 7 + (INT64)gp_pre_disp;
            g_EspState.tl_valid = (g_EspState.g_players_va >= 0x10000ULL) ? TRUE : FALSE;
            DEBUG_ESP("ESP_Init: g_players (pre-gate) instr=0x%I64X va=0x%I64X valid=%d",
                      gp_pre_instr, g_EspState.g_players_va, g_EspState.tl_valid);
        }
    }

    /* FAST PATH: if disk cache fully populated everything, return now and
     * skip both the key scan and the datum scan entirely. */
    if (g_EspState.keys_valid && g_EspState.datum_valid &&
        g_EspState.matrices_valid && g_EspState.tl_valid) {
        DEBUG_ESP("ESP_Init: full cache hit — skipping all scans");
        return TRUE;
    }

    /* ── 1. Keys — Decryption keys are dynamically resolved via AOB + GetKeyFromFunction above. ── */

    /* ── 2. Datum table — multi-hit .text scan + handle-resolve validation ─ */
    if (!s_datumValidated) {
        /* Pattern: mov rdx, [rip+disp32]; cmp [rsi+...], ...  =  48 8B 15 ?? ?? ?? ?? 81 BE */
        #define DATUM_MAX_CAND 30
        struct {
            UINT64 tbl_va;
            UINT64 origin_ptr_va;
        } cand[DATUM_MAX_CAND] = {0};
        int    nCand = 0;

        /* Try resolving the cached static ptr_va first, avoiding the slow 110 MB memory scan. */
        if (s_cached_datum_va >= 0x10000ULL) {
            UINT64 ptr_va = s_cached_datum_va;
            UINT64 tbl_ptr_ptr = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, ptr_va, &tbl_ptr_ptr, 8);
            BYOVD_UNLOCK();

            UINT64 tbl_ptr = 0;
            if (tbl_ptr_ptr > 0x10000ULL && tbl_ptr_ptr < 0x800000000000ULL) {
                BYOVD_LOCK();
                BYOVD_ReadVA_NoCache(cr3, tbl_ptr_ptr, &tbl_ptr, 8);
                BYOVD_UNLOCK();
            }

            UINT64 cands_to_try[2] = { tbl_ptr_ptr, tbl_ptr };
            for (int k = 0; k < 2; k++) {
                UINT64 cur_cand = cands_to_try[k];
                if (cur_cand < 0x100000ULL || cur_cand >= 0x800000000000ULL) continue;
                if (nCand < DATUM_MAX_CAND) {
                    cand[nCand].tbl_va = cur_cand;
                    cand[nCand].origin_ptr_va = ptr_va;
                    nCand++;
                    char _l[120]; wsprintfA(_l,"[DATUM] cached_ptr cand #%d tbl=0x%I64X ptr_va=0x%I64X", nCand, cur_cand, ptr_va); WriteEspLog(_l);
                }
            }
        }

        /* If no candidates were retrieved from cache, run the live AOB scan over .text */
        if (nCand == 0) {
            /* Find candidates across all .text sections */
            for (int occ = 0; occ < 2; occ++) {
                UINT64 txt_base = 0, txt_len = 0;
                BYOVD_LOCK();
                BOOL tok = BYOVD_GetSectionBounds(cr3, d2base, ".text", occ, &txt_base, &txt_len);
                BYOVD_UNLOCK();
                if (!tok || !txt_base || !txt_len) continue;

                { char _l[96]; wsprintfA(_l,"[DATUM] Scanning .text section occ=%d base=0x%I64X len=0x%I64X", occ, txt_base, txt_len); WriteEspLog(_l); }

                UINT64 cursor = txt_base;
                UINT64 txt_end = txt_base + txt_len;
                while (cursor < txt_end && nCand < DATUM_MAX_CAND) {
                    BYOVD_LOCK();
                    UINT64 instr = BYOVD_ScanPattern(cr3, cursor, txt_end - cursor,
                                                     dt_pat, dt_mask, 9);
                    BYOVD_UNLOCK();
                    if (!instr || instr < cursor) break;
                    cursor = instr + 1;

                    INT32 disp = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA_NoCache(cr3, instr + 3, &disp, 4);
                    BYOVD_UNLOCK();
                    UINT64 ptr_va  = instr + 7 + (INT64)disp;
                    UINT64 tbl_ptr_ptr = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA_NoCache(cr3, ptr_va, &tbl_ptr_ptr, 8);
                    BYOVD_UNLOCK();

                    UINT64 tbl_ptr = 0;
                    if (tbl_ptr_ptr > 0x10000ULL && tbl_ptr_ptr < 0x800000000000ULL) {
                        BYOVD_LOCK();
                        BYOVD_ReadVA_NoCache(cr3, tbl_ptr_ptr, &tbl_ptr, 8);
                        BYOVD_UNLOCK();
                    }

                    {
                        char _db[180];
                        wsprintfA(_db, "[DATUM_DBG] match at 0x%I64X ptr_va=0x%I64X ptr_ptr=0x%I64X tbl_ptr=0x%I64X", instr, ptr_va, tbl_ptr_ptr, tbl_ptr);
                        WriteEspLog(_db);
                    }

                    /* Try both single and double pointer as candidates */
                    UINT64 cands_to_try[2] = { tbl_ptr_ptr, tbl_ptr };
                    for (int k = 0; k < 2; k++) {
                        UINT64 cur_cand = cands_to_try[k];
                        if (cur_cand < 0x100000ULL || cur_cand >= 0x800000000000ULL) continue;
                        
                        BOOL dup = FALSE;
                        for (int c = 0; c < nCand; c++) if (cand[c].tbl_va == cur_cand) { dup = TRUE; break; }
                        if (dup) continue;

                        if (nCand < DATUM_MAX_CAND) {
                            cand[nCand].tbl_va = cur_cand;
                            cand[nCand].origin_ptr_va = ptr_va;
                            nCand++;
                            char _l[120]; wsprintfA(_l,"[DATUM] cand #%d tbl=0x%I64X ptr_va=0x%I64X (instr=0x%I64X)", nCand, cur_cand, ptr_va, instr); WriteEspLog(_l);
                        }
                    }
                }
            }
        }
        { char _l[64]; wsprintfA(_l,"[DATUM] %d candidate(s) found", nCand); WriteEspLog(_l); }

        /* Score each candidate by structural integrity of its HandleBucket entries. */
        int bestIdx = -1, bestScore = 3;
        for (int ci = 0; ci < nCand; ci++) {
            int score = 0;
            for (int bi = 0; bi < 64; bi++) {
                UINT64 bucket_va = cand[ci].tbl_va + (UINT64)bi * 64ULL;
                UINT64 entries = 0;
                UINT32 stride  = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA_NoCache(cr3, bucket_va + 0x08, &entries, 8);
                BYOVD_ReadVA_NoCache(cr3, bucket_va + 0x30, &stride,  4);
                BYOVD_UNLOCK();
                if (entries > 0x10000ULL && entries < 0x800000000000ULL &&
                    stride > 0 && stride < 0x10000)
                    score++;
            }
            { char _l[120]; wsprintfA(_l,"[DATUM] cand #%d 0x%I64X struct_score=%d/64", ci+1, cand[ci].tbl_va, score); WriteEspLog(_l); }
            if (score > bestScore) { bestScore = score; bestIdx = ci; }
        }

        if (bestIdx >= 0) {
            g_EspState.datum_table_va = cand[bestIdx].tbl_va;
            g_EspState.datum_valid    = TRUE;
            s_datumValidated          = TRUE;
            /* Save the static origin ptr_va so we can cache it in disk! */
            s_cached_datum_va         = cand[bestIdx].origin_ptr_va;
            { char _l[120]; wsprintfA(_l,"[DATUM] VALIDATED tbl=0x%I64X ptr_va=0x%I64X (cand #%d score=%d/64)",
                cand[bestIdx].tbl_va, cand[bestIdx].origin_ptr_va, bestIdx+1, bestScore); WriteEspLog(_l); }
        } else {
            g_EspState.datum_table_va = 0;
            g_EspState.datum_valid    = FALSE;
            s_datumValidated          = FALSE;
            /* If we queried from cache and validation failed, invalidate cache to trigger fresh AOB scan next frame */
            if (s_cached_datum_va >= 0x10000ULL) {
                s_cached_datum_va = 0;
                WriteEspLog("[DATUM] Cached candidate validation failed — invalidating cache for next frame retry");
            } else {
                WriteEspLog("[DATUM] NO valid candidate found or score too low — waiting for retry");
            }
        }
        datum_validated_local = s_datumValidated;
        #undef DATUM_MAX_CAND
    }

    /* W2S and TigerList already resolved above (before fast-path gate). */

    /* Persist whatever we have to disk (keys + datum_va + view_mat_va) so
     * future runs hit the fast path.  Save only when something actually
     * changed vs cache. */
    {
        BOOL needSave = FALSE;
        /* Only persist datum_va if handle-resolve validated it. */
        if (g_EspState.datum_valid && datum_validated_local &&
            s_cached_datum_va >= 0x10000ULL) {
            needSave = TRUE;
        }
        if (g_EspState.matrices_valid && s_cached_view_va != g_EspState.view_mat_va) {
            s_cached_view_va = g_EspState.view_mat_va;
            needSave = TRUE;
        }
        if (needSave) {
            s_cachedBase = d2base;
            AobCacheRec rec;
            /* Preserve any other AOB fields written by other modules. */
            (void)AobCache_Read(d2base, d2Tds, &rec);
            rec.datum_va    = s_cached_datum_va;
            rec.view_mat_va = s_cached_view_va;
            AobCache_Write(d2base, d2Tds, &rec);
            DEBUG_ESP("ESP_Init: persisted aob cache (datum+view) to disk");
        }
    }

    /* keys_valid is the minimum requirement; datum_valid enables handle resolve */
    return g_EspState.keys_valid;
}

/* ── ESP_Reset ───────────────────────────────────────────────────────────── */
void ESP_Reset(void)
{
    g_EspState.view_mat_va    = 0;
    g_EspState.proj_mat_va    = 0;
    g_EspState.matrices_valid = FALSE;
}


#endif /* ESP_IMPLEMENTATION */
