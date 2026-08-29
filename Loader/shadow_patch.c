
/*
 * shadow_patch.c — Loader-side shadow patch table management.
 *
 * Creates a named Global section containing SHADOW_TABLE_U (same layout as
 * SHADOW_TABLE in the driver).  The driver maps this section in kernel space
 * and uses it in the MmCopyVirtualMemory hook to spoof reads by BattlEye.
 *
 * Section name: Global\SeraphSdwP  (XOR-obfuscated in code, key=0x37)
 * Section size: 0x2000 bytes
 *
 * Thread safety: a volatile CAS lock (same as the driver uses) serialises
 * all writes to the table.  Register/Unregister calls are infrequent so
 * a busy-wait spinlock is perfectly acceptable.
 */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include "shadow_patch.h"
#include "debug.h"
#include "ThemidaSDK.h"
#include <windows.h>

static HANDLE          s_hSection = NULL;
static SHADOW_TABLE_U* s_table    = NULL;

/* ── Section name: derived from C: volume serial per-machine ───────────────
   No static name in binary — each machine gets a unique section name.
   Both loader (shadow_patch.c) and driver (shadow_mem.c) derive the same
   name deterministically from the volume serial number.
   Format: Global\{XXXXXXXX-XXXX} where X = hex derived from vol serial.
   ───────────────────────────────────────────────────────────────────────── */
static void DecodeSectionName(wchar_t* out, int maxChars) {
    DWORD vol = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
    /* Mix bits for better distribution */
    DWORD h1 = vol * 0x9E3779B9u;
    h1 = (h1 << 13) | (h1 >> 19);
    h1 ^= 0xA5C3E1F7u;
    DWORD h2 = h1 * 0x85EBCA6Bu;
    h2 = (h2 << 7) | (h2 >> 25);
    _snwprintf_s(out, maxChars, _TRUNCATE,
        L"Global\\{%08X-%04X}", h1, (WORD)(h2 & 0xFFFF));
}

/* ── CAS spinlock helpers ───────────────────────────────────────────────── */
static void TableLock(void) {
    /* M-11: Guard against call before ShadowPatch_Init() */
    if (!s_table) return;
    while (InterlockedCompareExchange(&s_table->lock, 1L, 0L) != 0L)
        YieldProcessor();
}
static void TableUnlock(void) {
    if (!s_table) return;
    InterlockedExchange(&s_table->lock, 0L);
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowPatch_Init
   Creates (or opens if already exists) the named Global section, maps it,
   and initialises the SHADOW_TABLE header.
   Must be called BEFORE the driver opens the section (i.e. before BYOVD_Init
   loads the driver, or at minimum before any patch is applied).
   ══════════════════════════════════════════════════════════════════════════ */
#pragma optimize("", off)
BOOL ShadowPatch_Init(void) {
    /* MUTATE: section creation + name decoding + header init. The XOR-obfuscated
     * section name and magic constant are particularly attractive static signatures —
     * mutating the surrounding logic makes them harder to correlate. */
    MUTATE_START
    BOOL _spi_result = FALSE;
    if (s_table) { _spi_result = TRUE; goto _spi_end; }

    wchar_t name[32];
    DecodeSectionName(name, 32);

    s_hSection = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        SHADOW_SECTION_SIZE,
        name);

    if (!s_hSection) goto _spi_end;

    /* If section already existed (ERROR_ALREADY_EXISTS), we still get a handle
       and can map it.  The driver may have created it or a previous run is alive. */
    BOOL existed = (GetLastError() == ERROR_ALREADY_EXISTS);

    s_table = (SHADOW_TABLE_U*)MapViewOfFile(
        s_hSection,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        SHADOW_SECTION_SIZE);

    if (!s_table) { CloseHandle(s_hSection); s_hSection = NULL; goto _spi_end; }

    if (!existed) {
        /* Fresh section — write header */
        RtlSecureZeroMemory(s_table, SHADOW_SECTION_SIZE);
        s_table->lock  = 0;
        s_table->d2pid = 0;
        /* Set magic last so the driver validates it exists */
        InterlockedExchange((LONG*)&s_table->magic, (LONG)SHADOW_TABLE_MAGIC);
    }

    _spi_result = TRUE;
_spi_end:
    MUTATE_END
    return _spi_result;
}
#pragma optimize("", on)

/* ════════════════════════════════════════════════════════════════════════════
   ShadowPatch_Deinit — unmap and close.  Clears all entries first so the
   driver's hook stops spoofing immediately.
   ══════════════════════════════════════════════════════════════════════════ */
void ShadowPatch_Deinit(void) {
    if (!s_table) return;

    TableLock();
    for (int i = 0; i < SHADOW_MAX_ENTRIES; i++)
        s_table->entries[i].active = 0;
    s_table->d2pid = 0;
    TableUnlock();

    UnmapViewOfFile(s_table);  s_table    = NULL;
    CloseHandle(s_hSection);   s_hSection = NULL;
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowPatch_SetD2Pid — inform the driver of the current D2 process PID.
   Call after AttachToDestiny2() succeeds.
   ══════════════════════════════════════════════════════════════════════════ */
void ShadowPatch_SetD2Pid(DWORD pid) {
    if (!s_table) return;
    InterlockedExchange((LONG*)&s_table->d2pid, (LONG)pid);
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowPatch_Register
   Adds or updates an entry in the shared table so the driver's hook can
   substitute original bytes for this VA range.

   va       — D2 virtual address of the first patched byte
   original — original bytes (before the patch was written)
   size     — number of bytes (max SHADOW_MAX_BYTES)
   ══════════════════════════════════════════════════════════════════════════ */
#pragma optimize("", off)
BOOL ShadowPatch_Register(unsigned long long d2va,
                           const unsigned char* original,
                           unsigned long size) {
    /* MUTATE: this is the routine BattlEye-style anti-cheat reads back to detect
     * memory diffs. Mutating the slot-allocation + lock dance hides the table layout. */
    MUTATE_START
    BOOL _spr_result = FALSE;
    if (!s_table || !original || size == 0 || size > SHADOW_MAX_BYTES) goto _spr_end;

    TableLock();

    /* Check if this VA is already registered (update) */
    int slot = -1;
    for (int i = 0; i < SHADOW_MAX_ENTRIES; i++) {
        if (s_table->entries[i].active && s_table->entries[i].d2va == d2va) {
            slot = i;
            break;
        }
        if (slot < 0 && !s_table->entries[i].active) slot = i;
    }

    if (slot < 0) { TableUnlock(); goto _spr_end; }

    SHADOW_ENTRY_U* e = &s_table->entries[slot];
    e->d2va  = d2va;
    e->size  = size;
    for (UINT32 _i = 0; _i < size; _i++) ((UINT8*)e->original)[_i] = ((const UINT8*)original)[_i];
    InterlockedExchange(&e->active, 1L);

    TableUnlock();

    _spr_result = TRUE;
_spr_end:
    MUTATE_END
    return _spr_result;
}
#pragma optimize("", on)

/* ════════════════════════════════════════════════════════════════════════════
   ShadowPatch_Unregister — remove the entry for a given D2 VA.
   ══════════════════════════════════════════════════════════════════════════ */
void ShadowPatch_Unregister(unsigned long long d2va) {
    if (!s_table) return;

    TableLock();
    for (int i = 0; i < SHADOW_MAX_ENTRIES; i++) {
        if (s_table->entries[i].active && s_table->entries[i].d2va == d2va) {
            InterlockedExchange(&s_table->entries[i].active, 0L);
            break;
        }
    }
    TableUnlock();
}

