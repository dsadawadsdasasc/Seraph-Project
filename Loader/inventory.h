#pragma once
/* inventory.h — Destiny 2 inventory/loadout manipulation via BYOVD physical write.
 *
 * The inventory struct is located by scanning for a fixed header signature:
 *   00 00 00 00 07 00 00 00 01 00 00 00 01 00 00 00
 * which is stable across sessions.  The matched VA is s_invBase.
 *
 * Item slots store item/skin hashes as UINT32 values.  Writing a different
 * hash into a slot changes the item visually (and functionally for weapons).
 *
 * Known offsets (relative to struct base):
 *   Anchor: primary weapon ID confirmed at base+0x13C4 (session 2026-05-08).
 *   All offsets below = community reference + delta 0x2C from that anchor.
 *
 *   Weapons (primary / energy / heavy):
 *     KINETIC_TYPE     0x13C4   u16 — weapon type hash  ← CONFIRMED
 *     KINETIC_MODEL    0x13C6   u16 — skin/model hash
 *     KINETIC_SHADER_1 0x13EA   u16
 *     KINETIC_SHADER_2 0x13EE   u16
 *     KINETIC_SHADER_3 0x13F2   u16
 *     ENERGY_TYPE      0x1414   u16
 *     ENERGY_MODEL     0x1416   u16
 *     ENERGY_SHADER_1  0x143A   u16
 *     ENERGY_SHADER_2  0x143E   u16
 *     ENERGY_SHADER_3  0x1442   u16
 *     HEAVY_TYPE       0x1464   u16
 *     HEAVY_MODEL      0x1466   u16
 *     HEAVY_SHADER_1   0x148A   u16
 *     HEAVY_SHADER_2   0x148E   u16
 *     HEAVY_SHADER_3   0x1492   u16
 *   Armor:
 *     HELMET_MODEL     0x11E6   u16
 *     HELMET_SHADER_1  0x120A   u16
 *     HELMET_SHADER_2  0x120E   u16
 *     HELMET_SHADER_3  0x1212   u16
 *     ARMS_MODEL       0x1236   u16
 *     ARMS_SHADER_1    0x125A   u16
 *     ARMS_SHADER_2    0x125E   u16
 *     ARMS_SHADER_3    0x1262   u16
 *     CHEST_MODEL      0x12D6   u16
 *     CHEST_SHADER_1   0x12FA   u16
 *     CHEST_SHADER_2   0x12FE   u16
 *     CHEST_SHADER_3   0x1302   u16
 *     LEGS_MODEL       0x1326   u16
 *     LEGS_SHADER_1    0x134A   u16
 *     LEGS_SHADER_2    0x134E   u16
 *     LEGS_SHADER_3    0x1352   u16
 *     CLASS_ITEM_MODEL 0x1376   u16
 *   Cosmetics:
 *     GHOST_TYPE       0x1550   u16
 *     GHOST_MODEL      0x1556   u16
 *     SPARROW_TYPE     0x1504   u16
 *     SPARROW_MODEL    0x1506   u16
 *     SHIP_TYPE        0x14B4   u16
 *     SHIP_MODEL       0x14B6   u16
 *   Character:
 *     SUPER_TYPE       0x0D18   u16
 *     GRENADE_TYPE     0x0CD0   u16
 *     MELEE_TYPE       0x0D60   u16
 *     CLASS_ABILITY_TYPE 0x0FE8 u16
 *     MOBILITY         0x1A24   u16  (stat — write 0..100)
 *     RESILIENCE       0x1A2C   u16
 *     RECOVERY         0x1A34   u16
 *     DISCIPLINE       0x1A3C   u16
 *     INTELLECT        0x1A44   u16
 *     STRENGTH         0x1A4C   u16
 *
 * NOTE: Armor/cosmetic/stat offsets are derived (+0x2C delta from anchor).
 *       Verify via Inventory_DumpWeaponSlots() before writing.
 */
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Slot IDs ─────────────────────────────────────────────────────────── */
typedef enum {
    /* Weapons — anchor: primary ID at +0x13C4 CONFIRMED 2026-05-08 */
    INV_SLOT_KINETIC_TYPE     = 0x13C4,  /* primary weapon hash — CONFIRMED */
    INV_SLOT_KINETIC_MODEL    = 0x13C6,
    INV_SLOT_KINETIC_SHADER1  = 0x13EA,
    INV_SLOT_KINETIC_SHADER2  = 0x13EE,
    INV_SLOT_KINETIC_SHADER3  = 0x13F2,

    INV_SLOT_ENERGY_TYPE      = 0x1414,
    INV_SLOT_ENERGY_MODEL     = 0x1416,
    INV_SLOT_ENERGY_SHADER1   = 0x143A,
    INV_SLOT_ENERGY_SHADER2   = 0x143E,
    INV_SLOT_ENERGY_SHADER3   = 0x1442,

    INV_SLOT_HEAVY_TYPE       = 0x1464,
    INV_SLOT_HEAVY_MODEL      = 0x1466,
    INV_SLOT_HEAVY_SHADER1    = 0x148A,
    INV_SLOT_HEAVY_SHADER2    = 0x148E,
    INV_SLOT_HEAVY_SHADER3    = 0x1492,

    /* Armor — (+0x2C delta from community ref) */
    INV_SLOT_HELMET_MODEL     = 0x11E6,
    INV_SLOT_HELMET_SHADER1   = 0x120A,
    INV_SLOT_HELMET_SHADER2   = 0x120E,
    INV_SLOT_HELMET_SHADER3   = 0x1212,

    INV_SLOT_ARMS_MODEL       = 0x1236,
    INV_SLOT_ARMS_SHADER1     = 0x125A,
    INV_SLOT_ARMS_SHADER2     = 0x125E,
    INV_SLOT_ARMS_SHADER3     = 0x1262,

    INV_SLOT_CHEST_MODEL      = 0x12D6,
    INV_SLOT_CHEST_SHADER1    = 0x12FA,
    INV_SLOT_CHEST_SHADER2    = 0x12FE,
    INV_SLOT_CHEST_SHADER3    = 0x1302,

    INV_SLOT_LEGS_MODEL       = 0x1326,
    INV_SLOT_LEGS_SHADER1     = 0x134A,
    INV_SLOT_LEGS_SHADER2     = 0x134E,
    INV_SLOT_LEGS_SHADER3     = 0x1352,

    INV_SLOT_CLASS_ITEM_MODEL = 0x1376,

    /* Cosmetics — (+0x2C delta) */
    INV_SLOT_GHOST_TYPE       = 0x1550,
    INV_SLOT_GHOST_MODEL      = 0x1556,
    INV_SLOT_GHOST_SHADER1    = 0x157A,
    INV_SLOT_GHOST_SHADER2    = 0x157E,
    INV_SLOT_GHOST_SHADER3    = 0x1582,

    INV_SLOT_SPARROW_TYPE     = 0x1504,
    INV_SLOT_SPARROW_MODEL    = 0x1506,
    INV_SLOT_SPARROW_SHADER1  = 0x152A,
    INV_SLOT_SPARROW_SHADER2  = 0x152E,
    INV_SLOT_SPARROW_SHADER3  = 0x1532,

    INV_SLOT_SHIP_TYPE        = 0x14B4,
    INV_SLOT_SHIP_MODEL       = 0x14B6,
    INV_SLOT_SHIP_SHADER1     = 0x14DA,
    INV_SLOT_SHIP_SHADER2     = 0x14DE,
    INV_SLOT_SHIP_SHADER3     = 0x14E2,

    /* Character — (+0x2C delta) */
    INV_SLOT_SUPER_TYPE       = 0x0D18,
    INV_SLOT_GRENADE_TYPE     = 0x0CD0,
    INV_SLOT_MELEE_TYPE       = 0x0D60,
    INV_SLOT_CLASS_ABILITY    = 0x0FE8,

    INV_SLOT_MOBILITY         = 0x1A24,
    INV_SLOT_RESILIENCE       = 0x1A2C,
    INV_SLOT_RECOVERY         = 0x1A34,
    INV_SLOT_DISCIPLINE       = 0x1A3C,
    INV_SLOT_INTELLECT        = 0x1A44,
    INV_SLOT_STRENGTH         = 0x1A4C,
} InvSlotOffset;

/* ── Loadout preset ───────────────────────────────────────────────────── */
#define INV_PRESET_SLOTS  16   /* max u16 pairs per preset */

typedef struct {
    UINT32 offset;     /* InvSlotOffset value  */
    UINT16 value;      /* hash / stat value    */
} InvSlotEntry;

typedef struct {
    WCHAR       name[32];
    UINT32      count;
    InvSlotEntry slots[INV_PRESET_SLOTS];
} InvPreset;

#ifndef SERAPH_EXCLUDE_INVENTORY
/* ── Public API ───────────────────────────────────────────────────────── */

/* Call after AttachToDestiny2 succeeds — scans for inventory base address. */
void Inventory_OnAttach(void);

/* Returns TRUE if the inventory struct was located. */
BOOL Inventory_IsReady(void);

/* Read a single u16 slot from the inventory struct. Returns 0 if not ready. */
UINT16 Inventory_ReadSlot(UINT32 offset);

/* Write a single u16 value to the given slot offset.
 * Returns TRUE on success. */
BOOL Inventory_WriteSlot(UINT32 offset, UINT16 value);

/* Apply a full preset (writes all InvSlotEntry items in preset). */
BOOL Inventory_ApplyPreset(const InvPreset *preset);

/* Dump all known weapon slots to the debug log (for offset verification). */
void Inventory_DumpWeaponSlots(void);

/* Reset state on detach. */
void Inventory_OnDetach(void);

#else
/* Stubs when SERAPH_EXCLUDE_INVENTORY is defined */
static inline void   Inventory_OnAttach(void)               {}
static inline BOOL   Inventory_IsReady(void)                { return FALSE; }
static inline UINT16 Inventory_ReadSlot(UINT32 o)           { (void)o; return 0; }
static inline BOOL   Inventory_WriteSlot(UINT32 o, UINT16 v){ (void)o;(void)v; return FALSE; }
static inline BOOL   Inventory_ApplyPreset(const InvPreset *p){ (void)p; return FALSE; }
static inline void   Inventory_DumpWeaponSlots(void)        {}
static inline void   Inventory_OnDetach(void)               {}
#endif /* SERAPH_EXCLUDE_INVENTORY */

#ifdef __cplusplus
}
#endif
