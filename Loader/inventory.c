/* inventory.c — Destiny 2 inventory/loadout manipulation.
 *
 * Locates the inventory struct by scanning for the fixed header:
 *   00 00 00 00 07 00 00 00 01 00 00 00 01 00 00 00
 *   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * (first 32 bytes observed to be stable; remainder is item data)
 *
 * The scan covers the D2 process heap/data range.  On match, s_invBase
 * stores the VA.  All subsequent reads/writes are BYOVD physical writes
 * at (s_invBase + offset).
 */
#include "inventory.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <string.h>
#include "aob_patterns.h"

#define INV_AOB_LEN    32u
#define INV_SCAN_SIZE  0x40000000ULL   /* 1 GB — covers D2 heap */

/* ── State ────────────────────────────────────────────────────────────── */
static UINT64 s_invBase = 0;

/* ── Internal helpers ─────────────────────────────────────────────────── */
static BOOL _ReadU16(UINT64 cr3, UINT32 offset, UINT16 *out) {
    UINT16 v = 0;
    BOOL ok = BYOVD_ReadVA(cr3, s_invBase + offset, &v, 2);
    if (ok) *out = v;
    return ok;
}

static BOOL _WriteU16(UINT64 cr3, UINT32 offset, UINT16 value) {
    return BYOVD_WriteVA_Fresh(cr3, s_invBase + offset, &value, 2);
}

/* ── Public API ───────────────────────────────────────────────────────── */

/* Heap scan range for D2 process.
 * The inventory struct lives in the D2 process heap, NOT inside the PE image.
 * Observed VA was ~0x21AFF179C5C on a test session.  We scan the user-space
 * heap range in two passes:
 *   Pass 1: 0x0000_0001_0000_0000 .. +1 GB  (lower heap)
 *   Pass 2: 0x0000_0010_0000_0000 .. +4 GB  (mid heap, covers ~0x21AFF... range)
 * Each BYOVD_ScanPattern call scans up to INV_SCAN_SIZE bytes at a time.      */
#define INV_HEAP_PASS1_BASE  0x000000010000000ULL
#define INV_HEAP_PASS2_BASE  0x000001000000000ULL
#define INV_HEAP_PASS3_BASE  0x000002000000000ULL

void Inventory_OnAttach(void) {
    s_invBase = 0;

    UINT64 cr3 = GetDestiny2CR3();
    DEBUG_FLY("Inventory_OnAttach: cr3=0x%I64X", cr3);
    if (!cr3) return;

    /* Pass 1 — lower heap */
    BYOVD_LOCK();
    s_invBase = BYOVD_ScanPattern(cr3, INV_HEAP_PASS1_BASE, INV_SCAN_SIZE,
                                  k_inv_pat, k_inv_mask, (UINT8)INV_AOB_LEN);
    BYOVD_UNLOCK();
    if (s_invBase) { DEBUG_FLY("Inventory: found (pass1) 0x%I64X", s_invBase); return; }

    /* Pass 2 — mid heap (~0x10_0000_0000 range) */
    BYOVD_LOCK();
    s_invBase = BYOVD_ScanPattern(cr3, INV_HEAP_PASS2_BASE, INV_SCAN_SIZE,
                                  k_inv_pat, k_inv_mask, (UINT8)INV_AOB_LEN);
    BYOVD_UNLOCK();
    if (s_invBase) { DEBUG_FLY("Inventory: found (pass2) 0x%I64X", s_invBase); return; }

    /* Pass 3 — upper heap (covers ~0x21AFF... range) */
    BYOVD_LOCK();
    s_invBase = BYOVD_ScanPattern(cr3, INV_HEAP_PASS3_BASE, INV_SCAN_SIZE,
                                  k_inv_pat, k_inv_mask, (UINT8)INV_AOB_LEN);
    BYOVD_UNLOCK();
    if (s_invBase) { DEBUG_FLY("Inventory: found (pass3) 0x%I64X", s_invBase); return; }

    DEBUG_FLY("Inventory: NOT FOUND in any heap pass");
}

BOOL Inventory_IsReady(void) {
    return s_invBase != 0;
}

UINT16 Inventory_ReadSlot(UINT32 offset) {
    if (!s_invBase) return 0;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return 0;
    UINT16 v = 0;
    BYOVD_LOCK();
    _ReadU16(cr3, offset, &v);
    BYOVD_UNLOCK();
    return v;
}

BOOL Inventory_WriteSlot(UINT32 offset, UINT16 value) {
    if (!s_invBase) return FALSE;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;
    BYOVD_LOCK();
    BOOL ok = _WriteU16(cr3, offset, value);
    BYOVD_UNLOCK();
    DEBUG_FLY("Inventory_WriteSlot: off=0x%X val=0x%04X ok=%d", offset, (UINT32)value, ok);
    return ok;
}

BOOL Inventory_ApplyPreset(const InvPreset *preset) {
    if (!preset || !s_invBase) return FALSE;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;
    BOOL allOk = TRUE;
    BYOVD_LOCK();
    for (UINT32 i = 0; i < preset->count && i < INV_PRESET_SLOTS; i++) {
        if (!_WriteU16(cr3, preset->slots[i].offset, preset->slots[i].value)) {
            allOk = FALSE;
        }
    }
    BYOVD_UNLOCK();
    DEBUG_FLY("Inventory_ApplyPreset: count=%u allOk=%d", preset->count, allOk);
    return allOk;
}

void Inventory_DumpWeaponSlots(void) {
#ifndef NDEBUG
    if (!s_invBase) { DEBUG_FLY("Inventory_DumpWeaponSlots: not ready"); return; }
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    static const struct { const char *name; UINT32 off; } k_slots[] = {
        /* Weapons — anchor KIN_TYPE=0x13C4 CONFIRMED 2026-05-08 */
        { "KIN_TYPE",    0x13C4 }, { "KIN_MODEL",   0x13C6 },
        { "KIN_SH1",     0x13EA }, { "KIN_SH2",     0x13EE }, { "KIN_SH3",     0x13F2 },
        { "ENG_TYPE",    0x1414 }, { "ENG_MODEL",   0x1416 },
        { "ENG_SH1",     0x143A }, { "ENG_SH2",     0x143E }, { "ENG_SH3",     0x1442 },
        { "HVY_TYPE",    0x1464 }, { "HVY_MODEL",   0x1466 },
        { "HVY_SH1",     0x148A }, { "HVY_SH2",     0x148E }, { "HVY_SH3",     0x1492 },
        /* Armor — (+0x2C delta) */
        { "HELM_MODEL",  0x11E6 }, { "ARMS_MODEL",  0x1236 },
        { "CHEST_MODEL", 0x12D6 }, { "LEGS_MODEL",  0x1326 },
        { "CLASS_MODEL", 0x1376 },
        /* Cosmetics — (+0x2C delta) */
        { "GHOST_MDL",   0x1556 }, { "SPARROW_MDL", 0x1506 }, { "SHIP_MODEL",  0x14B6 },
        /* Stats — (+0x2C delta) */
        { "MOBILITY",    0x1A24 }, { "RESILIENCE",  0x1A2C }, { "RECOVERY",    0x1A34 },
        { "DISCIPLINE",  0x1A3C }, { "INTELLECT",   0x1A44 }, { "STRENGTH",    0x1A4C },
    };
    UINT32 nSlots = (UINT32)(sizeof(k_slots) / sizeof(k_slots[0]));
    BYOVD_LOCK();
    for (UINT32 i = 0; i < nSlots; i++) {
        UINT16 v = 0;
        _ReadU16(cr3, k_slots[i].off, &v);
        char buf[96];
        wsprintfA(buf, "[INV] %s @ +0x%04X = 0x%04X (%u)", k_slots[i].name, k_slots[i].off, (UINT32)v, (UINT32)v);
        DEBUG_FLY("%s", buf);
    }
    BYOVD_UNLOCK();
#endif
}

void Inventory_OnDetach(void) {
    s_invBase = 0;
    DEBUG_FLY("Inventory_OnDetach");
}
