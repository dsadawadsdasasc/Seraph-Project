#pragma once
/*
 * shadow_patch.h — Loader-side shadow patch table management.
 *
 * The loader creates a named Global section containing a SHADOW_TABLE.
 * The kernel driver maps that section and reads it in the MmCopyVirtualMemory
 * hook to substitute original bytes when BattlEye reads D2 memory.
 *
 * Call order:
 *   ShadowPatch_Init()                    — once, at startup (before BYOVD_Init)
 *   ShadowPatch_SetD2Pid(pid)             — after AttachToDestiny2()
 *   ShadowPatch_Register(va, orig, size)  — after Patch_Apply()
 *   ShadowPatch_Unregister(va)            — after Patch_Restore()
 *   ShadowPatch_Deinit()                  — on shutdown
 */
#include <windows.h>

/* Must match Driver/shadow_mem.h exactly */
#define SHADOW_MAX_ENTRIES  64
#define SHADOW_MAX_BYTES    64
#define SHADOW_TABLE_MAGIC  0x53484457UL

#pragma pack(push, 1)
typedef struct _SHADOW_ENTRY_U {
    unsigned long long d2va;
    unsigned long      size;
    volatile long      active;
    unsigned char      original[SHADOW_MAX_BYTES];
} SHADOW_ENTRY_U;

typedef struct _SHADOW_TABLE_U {
    volatile unsigned long magic;
    volatile long          lock;
    volatile unsigned long d2pid;
    unsigned long          _pad;
    SHADOW_ENTRY_U         entries[SHADOW_MAX_ENTRIES];
} SHADOW_TABLE_U;
#pragma pack(pop)

#define SHADOW_SECTION_SIZE 0x2000

BOOL ShadowPatch_Init(void);
void ShadowPatch_Deinit(void);
void ShadowPatch_SetD2Pid(DWORD pid);
BOOL ShadowPatch_Register(unsigned long long d2va,
                           const unsigned char* original,
                           unsigned long size);
void ShadowPatch_Unregister(unsigned long long d2va);
