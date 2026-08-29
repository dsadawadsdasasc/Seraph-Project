#pragma once
/*
 * shadow_mem.h — MmCopyVirtualMemory inline hook
 * Intercepts BattlEye cross-process reads targeting Destiny 2.
 * Substitutes original (unpatched) bytes so BE never sees our patches.
 *
 * Target: Win10 22H2 x64  |  Requires: no HVCI (NonPagedPool must be executable)
 */
#include <ntddk.h>

/* ── Shared layout (plain types — same struct is mapped by the loader) ─────── */
#define SHADOW_MAX_ENTRIES  64
#define SHADOW_MAX_BYTES    64
#define SHADOW_TABLE_MAGIC  0x53484457UL  /* "SHDW" */
#define SHADOW_SECTION_SIZE 0x2000        /* 8 KB — fits SHADOW_TABLE comfortably */

#pragma pack(push, 1)
typedef struct _SHADOW_ENTRY {
    unsigned long long d2va;                      /* D2 process VA of patched region */
    unsigned long      size;                      /* bytes patched (1–64)            */
    volatile long      active;                    /* 1 = registered, 0 = free        */
    unsigned char      original[SHADOW_MAX_BYTES];/* original bytes before patch     */
} SHADOW_ENTRY;

typedef struct _SHADOW_TABLE {
    volatile unsigned long magic;                 /* SHADOW_TABLE_MAGIC sanity check */
    volatile long          lock;                  /* 0=free 1=held (CAS spinlock)    */
    volatile unsigned long d2pid;                 /* Destiny 2 process PID           */
    unsigned long          _pad;
    SHADOW_ENTRY           entries[SHADOW_MAX_ENTRIES];
} SHADOW_TABLE;
#pragma pack(pop)

/* ── Driver-side context (kernel only) ─────────────────────────────────────── */
typedef struct _SHADOW_CTX {
    BOOLEAN         initialized;
    BOOLEAN         hookInstalled;
    PEPROCESS       d2Process;          /* cached D2 EPROCESS (ref held)       */
    PVOID           sectionKva;         /* kernel VA of the mapped section      */
    SHADOW_TABLE*   table;              /* == sectionKva                        */
    HANDLE          sectionHandle;
    PUCHAR          trampolineBuf;      /* 28-byte NonPagedPool executable stub */
    UCHAR           savedBytes[14];     /* first 14 bytes of MmCopyVirtualMemory*/
    PVOID           fnMmCopy;           /* MmCopyVirtualMemory VA               */
    volatile LONG   hookRefCount;       /* count of threads inside handler      */
} SHADOW_CTX;

/* ── API ────────────────────────────────────────────────────────────────────── */
NTSTATUS ShadowMem_Init(SHADOW_CTX* ctx);
VOID     ShadowMem_Deinit(SHADOW_CTX* ctx);
VOID     ShadowMem_UpdateD2Process(SHADOW_CTX* ctx);
