/*=============================================================================
 * sobject_list.h — SObject World Entity List
 *
 * DIFFERENT from TigerList (PObjects, 16 slots, stride 0x4F20).
 * This is the GLOBAL entity array containing EVERYTHING in the world:
 *   - Players
 *   - PvE enemies
 *   - Projectiles
 *   - Light sources
 *   - Objects / misc entities
 *
 * ── Architecture Overview ───────────────────────────────────────────────────
 *
 * The SObject list is a flat array of entries (stride = 0xE0, max = 4096).
 * Each entry (SObject) has a component handle at +0x4C that links to a chain
 * of behaviors/components via the Tiger Handle Pool.
 *
 * Two pointers give access:
 *
 *   1. STATIC BASE pointer (from entity loop AOB):
 *        AOB: 48 8B 05 ?? ?? ?? ?? 81 E1 FF 1F 00 00
 *             0F AF 0D ?? ?? ?? ?? 0F 10 84 01 C0 00 00 00
 *        Resolve: g_TigerListBase = *(u64*)(RIP_resolve(match, 3, 7))
 *        This gives the raw array base (NOT encrypted).
 *        Stride (0xE0) is also at RIP-relative from `0F AF 0D` match+4.
 *        Position at entity + 0xC0 (confirmed by movups xmm0, [rcx+rax+0C0h]).
 *
 *   2. ENCRYPTED pointer (from alternative AOB):
 *        AOB: 4C 8B 15 ? ? ? ? 83 FB ? 74 ? 81 E3
 *        This pointer requires ESP_DecryptPtr (PointerManager::Decrypt with
 *        key1/key2/key3) before use.
 *        Use when the static base is not available or as fallback.
 *
 * ── SObject Layout (stride 0xE0 per entry) ────────────────────────────────
 *
 *   +0x00  uint8_t[6]   padding / unknown
 *   +0x06  uint16_t     type           (entity type ID)
 *   +0x08  uint8_t[3]   padding
 *   +0x0B  uint8_t      alive_flag     (0 = dead, 1/255 = alive)
 *   +0x0C  uint8_t[0x40] padding       (0x0C..0x4B)
 *   +0x4C  uint32_t     comp_handle    (handle → component chain via datum_resolve)
 *   +0x50  uint8_t[0x70] padding       (0x50..0xBF)
 *   +0xC0  float[3]     position       (ENCRYPTED, requires decryption keys)
 *             ^^^ CONFIRMED by entity loop AOB: movups xmm0, [rcx+rax+0C0h]
 *   +0xD0  (alternate location seen in some builds — monitor both)
 *
 * ── Handle Resolution ─────────────────────────────────────────────────────
 *
 * Handles are 32-bit tickets resolved through a chunk-based pool system.
 *
 *   pool_ptr_ptr = d2base + HANDLE_POOL_ROOT_OFF
 *   pool_base    = *(u64*)(*(u64*)pool_ptr_ptr)
 *
 *   if h == 0xFFFFFFFF → invalid, return 0
 *
 *   salt   = h >> 13
 *   idx    = ((salt | 0xFFC0000) >> 18) & salt    ← guard: idx > 0x15000 reject
 *   cbase  = TIGER_HANDLE_TABLE + idx * 64
 *   row    = read DatumRowData from (cbase + 8)
 *   v11    = row.entry_base + row.stride * (h & 0x1FFF)   ← raw entry
 *   mask   = *(u64*)(v11 + 8)
 *   ptr    = v11 - (mask & (u64)(i32)row.adj)              ← pointer correction
 *   result = ptr > 0x1000000 ? ptr : 0
 *
 * ── Component Chain Walk ─────────────────────────────────────────────────
 *
 * Start with comp_handle from SObject+0x4C.
 * Each node in the chain is a datum entry:
 *
 *   +0x00  uint16_t     flags
 *   +0x02  uint16_t     type_ref
 *   +0x04  uint32_t     match_id
 *   +0x08  uint32_t     schema_h       (hash identifying the schema)
 *   +0x0C  uint32_t     data_h         (handle → actual component data)
 *   +0x10  uint8_t      state
 *   +0x18  uint32_t     next_h         (next component in chain)
 *
 * Walk (max 64 iterations for safety):
 *   h = comp_handle
 *   while h valid:
 *     raw = datum_resolve(h)
 *     read fields from raw
 *     if data_h valid → data_ptr = datum_resolve(data_h) or ESP_DecryptPtr
 *     h = *(u32*)(raw + 0x18)   ← advance
 *
 * ── Bone System (from component) ──────────────────────────────────────────
 *
 * Bones are stored inside a specific component in the chain.
 *
 *   comp + 0x180 → first bone transform
 *   stride       = 0x20 bytes per bone
 *
 *   for i in range(bone_count):
 *     bone_addr = comp + 0x180 + i * 0x20
 *     bone_x    = *(float*)(bone_addr + 0x10)   ← X position
 *     bone_y    = *(float*)(bone_addr + 0x14)   ← Y position
 *     bone_z    = *(float*)(bone_addr + 0x18)   ← Z position
 *
 * ── Known Entity Types ────────────────────────────────────────────────────
 *
 *   0x0103  = system entity (loader/UI)
 *   0x010B  = single live entity (common in loader pool)
 *   0x0111  = active system entity
 *   0xFEEF  = free-list slot (unused)
 *
 *   Player entity type TBD — not yet confirmed in world pool.
 *===========================================================================*/

#pragma once
#include <stdint.h>
#include <windows.h>
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define SOBJ_STRIDE             0xE0u        /* per-entity stride (confirmed, can hardcode) */
#define SOBJ_MAX_COUNT          4096u        /* max entities in array     */
#define SOBJ_CHAIN_WALK_MAX     64u          /* safety cap for component chain walk */

/* ── SObject field offsets (within stride) ──────────────────────────────── */
#define SOBJ_OFF_TYPE           0x08u        /* uint8_t: ObjectType type      */
#define SOBJ_OFF_ALIVE          0x09u        /* uint8_t: 0=dead, else alive   */
#define SOBJ_OFF_COMP_HANDLE    0x4Cu        /* uint32_t: Handle classHandle  */
#define SOBJ_OFF_ENC_POS_A      0xC0u        /* float[3]: position (AOB confirmed) */
#define SOBJ_OFF_ENC_POS_B      0x20u        /* float[3]: position (alternate, Vector4Encrypted pos) */

/* ── Handle pool / datum system constants ──────────────────────────────── */
#define SOBJ_HANDLE_INVALID     0xFFFFFFFFu  /* sentinel: invalid handle */
#define SOBJ_DATUM_ENTRY_SIZE   64u          /* bytes per chunk descriptor entry */
#define SOBJ_DATUM_MAX_IDX      0x15000u     /* safety guard for chunk index */
#define SOBJ_HANDLE_ENTRY_MASK  0x1FFFu      /* lower bits mask for entry index */

/* ── Tiger Handle Tag Pattern ────────────────────────────────────────────── *
 * Valid Tiger Engine handles have byte 2 (mask 0x00FF0000) == 0xF9.
 * Use to pre-filter before calling datum_resolve.                         */
#define SOBJ_HANDLE_TAG         0x00F90000u

/* ── Component chain node offsets (within datum entry) ─────────────────── */
#define SOBJ_COMP_OFF_FLAGS     0x00u        /* uint16_t */
#define SOBJ_COMP_OFF_TYPE_REF  0x02u        /* uint16_t */
#define SOBJ_COMP_OFF_MATCH_ID  0x04u        /* uint32_t */
#define SOBJ_COMP_OFF_SCHEMA_H  0x08u        /* uint32_t */
#define SOBJ_COMP_OFF_DATA_H    0x0Cu        /* uint32_t */
#define SOBJ_COMP_OFF_STATE     0x10u        /* uint8_t  */
#define SOBJ_COMP_OFF_NEXT_H    0x18u        /* uint32_t */

/* ── Bone component offsets ────────────────────────────────────────────── */
#define SOBJ_BONE_COUNT_OFF     0x140u       /* int32_t: number of bones */
#define SOBJ_BONE_ARRAY_OFF     0x180u       /* first bone transform     */

#define SOBJ_BONE_STRIDE        0x20u        /* bytes per bone entry     */
#define SOBJ_BONE_POS_X         0x10u        /* float: X within bone entry */
#define SOBJ_BONE_POS_Y         0x14u        /* float: Y within bone entry */
#define SOBJ_BONE_POS_Z         0x18u        /* float: Z within bone entry */


/* ═══════════════════════════════════════════════════════════════════════════
 * AOB PATTERNS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Position Decryption Key4 AOB ─────────────────────────────────────────── *
 *    E8 ?? ?? ?? ?? 33 E8 E8
 *    The call is to cff_decrypt_float (or a wrapper).
 *    Key4 is the imm32 embedded at a fixed offset after the call.
 *    This is DIFFERENT from the HP key4 (E8 ?? ?? ?? ?? 48 63 D0 BE).
 *    Position encrypted float algorithm uses the same cff_decrypt_float
 *    state machine but potentially with a different key4 value.
 *
 *    Resolution: scan .text for E8 ?? ?? ?? ?? 33 E8 E8
 *    key4 = *(u32*)(match + KEY4_POS_IMM_OFF)                                        */
#define SOBJ_AOB_KEY4_POS \
    "\xE8\x00\x00\x00\x00\x33\xE8\xE8"
#define SOBJ_MASK_KEY4_POS \
    "\xFF\x00\x00\x00\x00\xFF\xFF\xFF"
#define SOBJ_AOB_KEY4_POS_LEN     8u
/* Key4 position offset — TBD at runtime.
 * The existing HP key4 pattern reads imm32 at match+9 (E8+4+movsxd+BE+imm32).
 * For this AOB (E8 disp32[5] + 33 E8[2] + E8[1]) the key could be:
 *   - match + 5 + (look for BE after the second E8) → e.g. match + 14
 *   - OR the key is embedded as a separate immediate in the function
 * Set to 0 initially; confirm via runtime diagnostics. */
#define SOBJ_KEY4_POS_IMM_OFF     0u

/* ── Fallback: HP key4 AOB (maybe same, maybe different) ────────────────────
 *    E8 ?? ?? ?? ?? 48 63 D0 BE
 *    Existing project key4 pattern (used for HP float).  If position uses the
 *    same key, this duplicates the scan in ESP_Init — just use g_EspState.key4. */
#define SOBJ_AOB_KEY4_HP \
    "\xE8\x00\x00\x00\x00\x48\x63\xD0\xBE"
#define SOBJ_MASK_KEY4_HP \
    "\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"

/* ── Entity Loop AOB ─────────────────────────────────────────────────────── *
 *   48 8B 05 ?? ?? ?? ??      mov     rax, cs:TigerListBase
 *   81 E1 FF 1F 00 00         and     ecx, 1FFFh
 *   0F AF 0D ?? ?? ?? ??      imul    ecx, dword ptr cs:SizeOfEachEntityEntry
 *   0F 10 84 01 C0 00 00 00   movups  xmm0, xmmword ptr [rcx+rax+0C0h]
 *
 * Resolution:
 *   match[0..6]  → 48 8B 05 ?? ?? ?? ??      → RIP-resolve at +3 (len 7) = TigerListBase
 *   match[13..19] → 0F AF 0D ?? ?? ?? ??      → RIP-resolve at +16 (len 7) = Stride
 *   Position at entity + 0xC0                                                 */
#define SOBJ_AOB_ENTITY_LOOP \
    "\x48\x8B\x05\x00\x00\x00\x00" \
    "\x81\xE1\xFF\x1F\x00\x00" \
    "\x0F\xAF\x0D\x00\x00\x00\x00" \
    "\x0F\x10\x84\x01\xC0\x00\x00\x00"
#define SOBJ_MASK_ENTITY_LOOP \
    "\xFF\xFF\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
#define SOBJ_AOB_ENTITY_LOOP_LEN  28u

/* ── Handle Pool Root AOB (option 1) ─────────────────────────────────────── *
 *   48 89 1D ?? ?? ?? ??      mov     cs:HandlePoolRoot, rbx
 *   48 8B CB                   mov     rcx, rbx
 *   E8 ?? ?? ?? ??             call    sub_xxxxx
 *   48 8B 43 20                mov     rax, [rbx+20h]
 *                                                                             */
#define SOBJ_AOB_POOL_ROOT_1 \
    "\x48\x89\x1D\x00\x00\x00\x00" \
    "\x48\x8B\xCB" \
    "\xE8\x00\x00\x00\x00" \
    "\x48\x8B\x43\x20"
#define SOBJ_MASK_POOL_ROOT_1 \
    "\xFF\xFF\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF" \
    "\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF\xFF"
#define SOBJ_AOB_POOL_ROOT_1_LEN  19u

/* ── Handle Pool Root AOB (option 2, with XOR edx,edx) ───────────────────── *
 *   48 89 1D ?? ?? ?? ??      mov     cs:HandlePoolRoot, rbx
 *   48 8B CB                   mov     rcx, rbx
 *   E8 ?? ?? ?? ??             call    sub_xxxxx
 *   48 8B 43 20                mov     rax, [rbx+20h]
 *   33 D2                      xor     edx, edx                              */
#define SOBJ_AOB_POOL_ROOT_2 \
    "\x48\x89\x1D\x00\x00\x00\x00" \
    "\x48\x8B\xCB" \
    "\xE8\x00\x00\x00\x00" \
    "\x48\x8B\x43\x20" \
    "\x33\xD2"
#define SOBJ_MASK_POOL_ROOT_2 \
    "\xFF\xFF\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF" \
    "\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\xFF\xFF" \
    "\xFF\xFF"
#define SOBJ_AOB_POOL_ROOT_2_LEN  21u

/* ── Encrypted SObject Pointer AOB ───────────────────────────────────────── *
 *   4C 8B 15 ? ? ? ?      mov     r10, [rip+disp32]    ← encrypted ptr
 *   83 FB ?                cmp     ebx, ??              ← discriminator
 *   74 ?                   je      ...
 *   81 E3                  and     ebx, ...
 *
 * This pointer MUST be decrypted via ESP_DecryptPtr before use.
 * Falls back to the static TigerListBase if this scan fails.               */
#define SOBJ_AOB_ENC_PTR \
    "\x4C\x8B\x15\x00\x00\x00\x00" \
    "\x83\xFB\x00\x74\x00\x81\xE3"
#define SOBJ_MASK_ENC_PTR \
    "\xFF\xFF\xFF\x00\x00\x00\x00" \
    "\xFF\xFF\x00\xFF\x00\xFF\xFF"
#define SOBJ_AOB_ENC_PTR_LEN   14u

/* ═══════════════════════════════════════════════════════════════════════════
 * DATA STRUCTURES
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ObjectType enum from scriptable entity definitions */
typedef enum {
    OBJ_TYPE_INVALID             = -1,
    OBJ_TYPE_NULL                = 0,
    OBJ_TYPE_INTERACTABLE_OBJECT = 1,
    OBJ_TYPE_DECORATION          = 4,
    OBJ_TYPE_RAGDOLL_PROP        = 6,
    OBJ_TYPE_AD_SPAWN_LOCATION   = 7,
    OBJ_TYPE_EXPLODABLE          = 8,
    OBJ_TYPE_DYNAMIC             = 11,
    OBJ_TYPE_PLAYABLE_ENTITY     = 12,
    OBJ_TYPE_WEAPON              = 14,
    OBJ_TYPE_VEHICLE             = 15,
    OBJ_TYPE_VEHICLE_ENTITY      = 16,
    OBJ_TYPE_DECAL               = 17,
    OBJ_TYPE_PROJECTILE          = 18,
    OBJ_TYPE_AMMO                = 20,
    OBJ_TYPE_GENERAL_PICKUP      = 21,
    OBJ_TYPE_STATIC_MESH         = 28
} ObjectType_t;

/* Raw SObject entry (stride 0xE0) */
#pragma pack(push, 1)
typedef struct {
    uint32_t objectHandle;       /* 0x00 — Handle objectHandle */
    uint32_t pad_04;             /* 0x04 */
    uint8_t  type;               /* 0x08 — ObjectType type */
    uint8_t  alive;              /* 0x09 — alive flag */
    uint8_t  type_flags;         /* 0x0A — entity classification flags */
    uint8_t  pad_0B[5];          /* 0x0B..0x0F */
    float    rotation[4];        /* 0x10 — Quat rotation */
    float    enc_pos_0x20[4];    /* 0x20 — Vector4Encrypted position */
    uint8_t  pad_30[28];         /* 0x30..0x4B */
    uint32_t comp_handle;        /* 0x4C — Handle classHandle */
    uint8_t  pad_50[112];        /* 0x50..0xBF */
    float    enc_pos[3];         /* 0xC0 — encrypted position (alternate / AOB matched) */
    uint8_t  pad_CC[16];         /* 0xCC..0xDB */
    uint32_t enc_scale;          /* 0xDC — encrypted float scale (SOBJ_OFF_ENC_SCALE) */
    uint8_t  pad_E0[3];          /* 0xE0..0xE2 (padding to stride) */
} SObjectRaw;
#pragma pack(pop)


/* Component chain node (inside datum entry) */
#pragma pack(push, 1)
typedef struct {
    uint16_t flags;              /* 0x00 */
    uint16_t type_ref;           /* 0x02 */
    uint32_t match_id;           /* 0x04 */
    uint32_t schema_h;           /* 0x08 — schema hash */
    uint32_t data_h;             /* 0x0C — handle to actual component data */
    uint8_t  state;              /* 0x10 */
    uint8_t  pad_11[7];          /* 0x11..0x17 */
    uint32_t next_h;             /* 0x18 — next component in chain */
} SObjectCompNode;
#pragma pack(pop)

/* Chunk descriptor (DatumRowData, 64 bytes per idx) */
#ifndef DATUM_ROW_DATA_DEFINED
#define DATUM_ROW_DATA_DEFINED
#pragma pack(push, 1)
typedef struct {
    uint64_t entry_base;         /* +0x00: base of datum entries array */
    uint8_t  pad_10[0x20];       /* +0x08..0x27 */
    uint32_t stride;             /* +0x28: stride per entry */
    int32_t  adj;                /* +0x2C: adjustment mask for pointer correction */
} DatumRowData;
#pragma pack(pop)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * STATE
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* Resolved pointers */
    UINT64 tiger_list_base;          /* Static entity array base (from entity AOB) */
    UINT64 stride;                   /* Entity stride (0xE0, from AOB or hardcoded) */
    UINT64 count_ptr_va;             /* VA of count field (d2base + count_off or scanned) */
    UINT64 handle_pool_root;         /* Handle pool root VA (from AOB) */
    UINT64 datum_table_va;           /* Tiger Handle Table VA (from AOB in esp.h) */
    UINT64 enc_ptr_va;               /* VA of encrypted SObject pointer (from 4C 8B 15 AOB) */

    /* Decrypted values */
    UINT64 enc_ptr_decrypted;        /* Decrypted value of enc_ptr_va (0 = not used) */
    uint32_t pos_key4;               /* Position decryption key4 (from SOBJ_AOB_KEY4_POS scan) */

    /* Capabilities */
    BOOL   has_static_base;          /* TRUE if TigerListBase resolved */
    BOOL   has_enc_ptr;              /* TRUE if encrypted ptr AOB found */
    BOOL   has_pool_root;            /* TRUE if handle pool root resolved */
    BOOL   has_pos_key4;             /* TRUE if position key4 scanned */
    BOOL   datum_valid;              /* TRUE if TIGER_HANDLE_TABLE is set */
    BOOL   initialized;              /* TRUE after successful Init */
} SObjectListState;

extern SObjectListState g_sobjState;

/* ═══════════════════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/* Initialize: scan all AOBs, resolve static pointers and encrypted pointer.
 * Call after game attach (ESP_Init must have run first for datum keys).
 * Returns TRUE if at least one path to entity array was resolved.          */
BOOL SObjectList_Init(void);

/* Reset all cached state. Call on detach / game exit. */
void SObjectList_Reset(void);

/* Returns TRUE if at least one entity array access path is ready. */
BOOL SObjectList_IsReady(void);

/* ── Entity Array Access ────────────────────────────────────────────────── */

/* Get the resolved entity array base (from whichever method succeeded).
 * Returns 0 if not ready.                                                   */
UINT64 SObjectList_GetArrayBase(void);

/* Get the entity stride (should always be 0xE0). */
UINT64 SObjectList_GetStride(void);

/* Get the max entity count (should always be 4096). */
UINT32 SObjectList_GetMaxCount(void);

/* ── Per-Entity Reads ───────────────────────────────────────────────────── */

/* Read a single SObject entry by index. Returns TRUE on success.
 * out must point to a SObjectRaw struct.                                    */
BOOL SObjectList_ReadEntity(UINT32 index, SObjectRaw *out);

/* Read the entity type. Returns OBJ_TYPE_INVALID on failure. */
uint8_t SObjectList_ReadType(UINT32 index);

/* Read the alive flag. Returns FALSE (dead) on failure. */
BOOL SObjectList_ReadAlive(UINT32 index);

/* Read the component handle. Returns 0 on failure. */
uint32_t SObjectList_ReadCompHandle(UINT32 index);

/* Read the encrypted position. Returns TRUE on success. */
BOOL SObjectList_ReadEncPos(UINT32 index, float out_xyz[3]);

/* Decrypt a single encrypted position float using cff_decrypt_float state machine.
 * encrypted = raw u32 value read from the entity field
 * key4      = position decryption key (scanned via SOBJ_AOB_KEY4_POS)         */
float  SObjectList_DecryptPosFloat(uint32_t encrypted, uint32_t key4);

/* Decrypt all 3 position components. Returns TRUE on success.
 * Falls back to using g_EspState.key4 if pos_key4 is 0.                      */
BOOL   SObjectList_DecryptPosition(const float enc_xyz[3], uint32_t key4,
                                   float out_xyz[3]);

/* Scan for the position decryption key4 using AOB:
 *   E8 ?? ?? ?? ?? 33 E8 E8
 * Returns 0 on failure.                                                      */
uint32_t SObjectList_ScanPosKey4(void);

/* ── Handle Resolution ─────────────────────────────────────────────────── */

/* Check if a 32-bit value looks like a valid Tiger handle. */
static __inline BOOL SObject_IsValidHandle(uint32_t h)
{
    return h != 0 && h != 0xFFFFFFFFu && (h & 0x00FF0000u) == SOBJ_HANDLE_TAG;
}

/* Resolve a 32-bit handle into a real pointer via datum table.
 * datum_table_va comes from g_EspState.datum_table_va (ESP_Init must be done).
 * Returns 0 on failure.                                                     */
UINT64 SObjectList_ResolveHandle(UINT64 cr3, uint32_t h);

/* ── Component Chain Walk ──────────────────────────────────────────────── */

/* Walk the component chain starting from comp_handle.
 * Calls callback(node_ptr, ctx) for each valid node.
 * Max SOBJ_CHAIN_WALK_MAX iterations for safety.
 * Returns number of nodes visited.                                          */
typedef void (*SObjectCompCallback)(UINT64 node_ptr, void *ctx);
int SObjectList_WalkComponents(UINT64 cr3, uint32_t comp_handle,
                               SObjectCompCallback callback, void *ctx);

/* ── Bone Reading ───────────────────────────────────────────────────────── */

/* Read bone count from a component node. Returns -1 on failure. */
int SObjectList_ReadBoneCount(UINT64 cr3, UINT64 comp_ptr);

/* Read bone positions from a component node.
 * Fills out_bones[3] per entry (x, y, z) up to max_bones.
 * Returns number of bones read (0 on failure).                              */
int SObjectList_ReadBones(UINT64 cr3, UINT64 comp_ptr,
                          float *out_bones, int max_bones);

/* ── Utility: Validate Entity Position ──────────────────────────────────── */

/* Basic sanity check: no NaN, no inf, magnitude in reasonable range. */
BOOL SObjectList_IsPositionValid(const float pos[3]);

#ifdef __cplusplus
}
#endif
