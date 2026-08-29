/*
 * dma_mem.hpp  --  DMA memory engine header (replaces byovd.h entirely).
 *
 * Design principles for the DMA version:
 *   - Scanning reads whole sections into a local buffer (1 MB chunks) and
 *     searches locally — O(n/1MB) FPGA round-trips instead of O(n/4KB).
 *   - Scatter reads/writes batch multiple addresses into one FPGA transaction.
 *   - No kernel driver, no IOCTL, no syscalls, no Themida, no process spoofing.
 *   - Lock (g_dmaLock) is a std::mutex — only VMMDLL handle concurrency is
 *     protected; per-read serialization is NOT needed (DMA is inherently safe
 *     to read/write concurrently from different threads without driver state).
 *   - All functions are extern "C" so .c feature files compile unchanged.
 */
#pragma once
#include <windows.h>
#include <stdint.h>

/* ── Lock API ────────────────────────────────────────────────────────────────
 * The underlying lock is a std::mutex (defined in dma_mem.cpp).
 * C++ code uses direct calls; C code uses extern "C" wrappers so .c feature
 * files compile without pulling in C++ headers.
 * ─────────────────────────────────────────────────────────────────────────── */
#ifdef __cplusplus
#include <mutex>
extern std::mutex g_dmaLock;
#define DMA_LOCK()    g_dmaLock.lock()
#define DMA_UNLOCK()  g_dmaLock.unlock()
#define DMA_TRYLOCK() (g_dmaLock.try_lock())
#else
/* C-compatible wrappers — implemented in dma_mem.cpp */
void DMA_LockAcquire(void);
void DMA_LockRelease(void);
BOOL DMA_LockTryAcquire(void);
#define DMA_LOCK()    DMA_LockAcquire()
#define DMA_UNLOCK()  DMA_LockRelease()
#define DMA_TRYLOCK() DMA_LockTryAcquire()
#endif

/* Redirect BYOVD macros → DMA so every feature file compiles as-is */
#define BYOVD_LOCK()                DMA_LOCK()
#define BYOVD_UNLOCK()              DMA_UNLOCK()
#define BYOVD_TRYLOCK()             DMA_TRYLOCK()
#define BYOVD_Init()                DMA_Init()
#define BYOVD_Shutdown()            DMA_Shutdown()
#define BYOVD_ReadVA(cr3, va, buf, size) DMA_ReadVA(cr3, va, buf, size)
#define BYOVD_ReadVA_NoCache(cr3, va, buf, size) DMA_ReadVA(cr3, va, buf, size)
/* BYOVD_WriteVA → standard virtual-address write (same as Vanish/other DMA tools).
 * VMMDLL_MemWrite by VA works for both .data and .text in MemProcFS. */
#define BYOVD_WriteVA(cr3, va, buf, size)       DMA_WriteVA(cr3, va, buf, size)
#define BYOVD_WriteVA_Fresh(cr3, va, buf, size) DMA_WriteVAPhys(va, buf, size)
#define BYOVD_ReadBatch             DMA_ReadBatch
#define BYOVD_READ_BATCH_ENTRY      DMA_READ_BATCH_ENTRY
#define BYOVD_FindProcessCR3        DMA_FindProcessCR3
#define BYOVD_FindProcessInfo       DMA_FindProcessInfo
#define BYOVD_InvalidateProcessCache DMA_InvalidateProcessCache
#define BYOVD_GetModuleBase         DMA_GetModuleBase
#define BYOVD_GetSectionBounds      DMA_GetSectionBounds
#define BYOVD_GetTextBounds         DMA_GetTextBounds
#define BYOVD_GetImageBounds        DMA_GetImageBounds
#define BYOVD_GetDataBounds         DMA_GetDataBounds
#define BYOVD_ScanPattern           DMA_ScanPattern
#define BYOVD_ScanPatternRaw(cr3, base, len, pat, mask, plen) \
    DMA_ScanPattern(cr3, base, len, pat, mask, plen)
/* DMA: ScanPatternText / ScanMultiPatternText use ParseSections to find
 * precise .text bounds. The full-image fallback (0x20000000ULL) was causing
 * false-positive AOB matches across non-text sections (heap, .data, .rdata).
 * Features that need full-module scan (e.g. vischeck) call DMA_ScanPattern
 * directly with explicit bounds from BYOVD_GetImageBounds. */
#define BYOVD_ScanPatternText(cr3,mod,pat,mask,len) \
    DMA_ScanPatternText(cr3,mod,pat,mask,len)
#define BYOVD_ScanMultiPatternText(cr3,mod,entries,cnt) \
    DMA_ScanMultiPatternText(cr3,mod,entries,cnt)
#define BYOVD_ScanPatternTextRaw(cr3,mod,pat,mask,len) \
    DMA_ScanPatternText(cr3,mod,pat,mask,len)
#define BYOVD_ScanPatternData       DMA_ScanPatternData
#define BYOVD_ScanMultiPattern      DMA_ScanMultiPattern
#define BYOVD_ScanMultiPatternData  DMA_ScanMultiPatternData
#define BYOVD_SpoofProcessImageName DMA_SpoofProcessImageName
#define BYOVD_SetPageWritable(cr3, va) DMA_SetPageWritable(va)
#define BYOVD_RestorePageReadOnly(cr3, va) DMA_RestorePageReadOnly(va)
#define BYOVD_FlushPhysCache()         DMA_FlushPhysCache()
/* DMA keyboard: ALL keys are read from the GAMING PC keyboard via DMA
 * (gafAsyncKeyState in win32kbase.sys).  The operator plays directly on
 * the PC with the FPGA card — keyboard is plugged into that machine, not
 * the LOADER PC.  BYOVD_IsKeyDown reads victim-PC keys through DMA.
 * Falls back to FALSE if keyboard thread not initialized (init is
 * idempotent and happens automatically during AttachToDestiny2).
 * On non-DMA builds (BYOVD/Loader) resolves to GetAsyncKeyState. */
#ifdef SERAPH_DMA_BUILD
#define BYOVD_IsKeyDown(vk)            (DMA_IsKeyboardReady() ? DMA_IsKeyDown(vk) : FALSE)
#define BYOVD_IsKeyPressed(vk)         (DMA_IsKeyboardReady() ? DMA_IsKeyPressed(vk) : FALSE)
#define BYOVD_IsKeyReleased(vk)        (DMA_IsKeyboardReady() ? DMA_IsKeyReleased(vk) : FALSE)

/* Redirect ALL GetAsyncKeyState calls to the gaming PC's keyboard via DMA.
 * It reads from the LOADER PC by default, but on the DMA build the gaming
 * PC is a different machine — we must read keys through DMA.
 * Only a pressed/not-pressed check (no "was pressed since last call" edge
 * bit).  Files affected: gui.c, aimbot.c, bunnyhop.c, fly.c. */
#define GetAsyncKeyState(vk) \
    (DMA_IsKeyboardReady() ? (DMA_IsKeyDown(vk) ? (SHORT)0x8000 : (SHORT)0) \
                           : (GetAsyncKeyState)(vk))
#else
#define BYOVD_IsKeyDown(vk)            ((GetAsyncKeyState(vk) & 0x8000) != 0)
#define BYOVD_IsKeyPressed(vk)         ((GetAsyncKeyState(vk) & 0x8000) != 0)
#define BYOVD_IsKeyReleased(vk)        ((GetAsyncKeyState(vk) & 0x8001) == 1)
#endif

/* Type alias: BYOVD_SCAN_ENTRY == DMA_SCAN_ENTRY (same field layout).
 * Used in gui_core.cpp, esp.h, d2_patches.c as a stack-allocated array type. */
#define BYOVD_SCAN_ENTRY            DMA_SCAN_ENTRY

#ifdef __cplusplus
extern "C" {
#endif

/* SetPageWritable — modifies the PTE R/W bit for a .text page so the game's
 * CPU can write to the mailbox slot inside a code cave.  On DMA this must
 * walk the page tables physically (VMMDLL_MemVirt2Phys cannot modify PTEs). */
BOOL DMA_SetPageWritable(UINT64 va);
BOOL DMA_RestorePageReadOnly(UINT64 va);

/* ── Init / Shutdown ────────────────────────────────────────────────────── */
BOOL DMA_Init(void);
void DMA_Shutdown(void);

/* ── Process discovery ──────────────────────────────────────────────────── */
UINT64 DMA_FindProcessCR3(const char *imageName); /* PID lookup only — does not Attach */
BOOL   DMA_ProcessExists(const char *imageName);  /* for detach polling — no side effects */
BOOL   DMA_FindProcessInfo(const char *imageName, UINT64 *outCR3, UINT64 *outPebVA);
void   DMA_InvalidateProcessCache(void);
void   DMA_FlushPhysCache(void);
BOOL DMA_SpoofProcessImageName(const char *fakeName); /* no-op — different machine */
BOOL DMA_HasPhysFrame(UINT64 va);  /* TRUE if va has a valid physical frame (page in RAM) */
BOOL DMA_ReadVAPad    (UINT64 va, void *buf, ULONG size); /* read with ZEROPAD, no NOCACHE */
BOOL DMA_ReadVACached (UINT64 va, void *buf, ULONG size); /* read from MemProcFS cache (no flags) */

/* ── Memory read / write ────────────────────────────────────────────────── */
/* cr3 parameter kept for API compat — ignored in DMA mode (PID used internally) */
BOOL DMA_ReadVA (UINT64 cr3, UINT64 va, void *buf, ULONG size);
BOOL DMA_WriteVA     (UINT64 cr3, UINT64 va, const void *buf, ULONG size);
/* Physical write: VA->PA per 4KB page, then writes with dwPID=-1.
 * Use for .text hooks/caves where virtual write may fail on large-page PTEs. */
BOOL DMA_WriteVAPhys (UINT64 va, const void *buf, ULONG size);

/* ── Scatter batch API ──────────────────────────────────────────────────── */
/* Begin a scatter batch, add reads, execute all at once, free.
 * Reduces N FPGA round-trips to 1. */
typedef void* DMA_SCATTER_HANDLE;
DMA_SCATTER_HANDLE DMA_ScatterBegin(void);
BOOL DMA_ScatterAddRead(DMA_SCATTER_HANDLE h, UINT64 va, void *buf, UINT32 size);
BOOL DMA_ScatterExecute(DMA_SCATTER_HANDLE h);
void DMA_ScatterFree(DMA_SCATTER_HANDLE h);

typedef struct {
    UINT64 va;
    void  *buf;
    ULONG  size;
} DMA_READ_BATCH_ENTRY;

BOOL DMA_ReadBatch(UINT64 cr3, DMA_READ_BATCH_ENTRY *entries, int count);

/* ── Module / section helpers ───────────────────────────────────────────── */
UINT64 DMA_GetModuleBase(UINT64 cr3, UINT64 peb_va, const wchar_t *modName);
BOOL   DMA_GetTextBounds (UINT64 cr3, UINT64 moduleBase, UINT64 *outVA, UINT64 *outLen);
BOOL   DMA_GetImageBounds(UINT64 cr3, UINT64 moduleBase, UINT64 *outVA, UINT64 *outLen);
BOOL   DMA_GetDataBounds (UINT64 cr3, UINT64 moduleBase, UINT64 *outVA, UINT64 *outLen);

/* ── Pattern scanning ───────────────────────────────────────────────────── */
/* mask: 0xFF = match, 0x00 = wildcard */
UINT64 DMA_ScanPattern    (UINT64 cr3, UINT64 base, UINT64 len,
                            const UINT8 *pat, const UINT8 *mask, UINT8 patLen);
UINT64 DMA_ScanPatternText(UINT64 cr3, UINT64 modBase,
                            const UINT8 *pat, const UINT8 *mask, UINT8 patLen);
UINT64 DMA_ScanPatternData(UINT64 cr3, UINT64 modBase,
                            const UINT8 *pat, const UINT8 *mask, UINT8 patLen);
/* Heap-wide scan: enumerates VAD non-image regions and scans each one.
 * Use when the pattern is heap-allocated and not inside the PE image. */
UINT64 DMA_ScanPatternHeap(UINT64 cr3, const UINT8 *pat, const UINT8 *mask, UINT8 patLen);
BOOL   DMA_GetSectionBounds(UINT64 cr3, UINT64 moduleBase, const char *name, int occurrence, UINT64 *va, UINT64 *len);

typedef struct {
    const UINT8 *pattern;
    const UINT8 *mask;
    UINT8        patLen;
    UINT64       scanLimit; /* 0 = use full len */
    UINT64       result;    /* out */
} DMA_SCAN_ENTRY;

/* Multi-pattern single-pass: reads each chunk once, tests all patterns.
 * Returns number of patterns found. */
int DMA_ScanMultiPattern    (UINT64 cr3, UINT64 base, UINT64 len,
                              DMA_SCAN_ENTRY *entries, int count);
int DMA_ScanMultiPatternText(UINT64 cr3, UINT64 modBase,
                              DMA_SCAN_ENTRY *entries, int count);
int DMA_ScanMultiPatternData(UINT64 cr3, UINT64 modBase,
                              DMA_SCAN_ENTRY *entries, int count);

/* ── DMA Keyboard (victim-PC keys) ──────────────────────────────────────── */
/* Polls gafAsyncKeyState in the victim's win32kbase.sys via VMMDLL.
 * Returns TRUE if the virtual key is currently held on the gaming PC.
 * Keyboard init is called automatically during AttachToDestiny2.
 * DMA_IsKeyboardReady() checks whether the keyboard thread is active.
 * If DMA keyboard is not available (headless gaming PC, or winlogon/
 * win32k access fails), BYOVD_IsKeyDown macros automatically fall back
 * to the LOADER PC's local GetAsyncKeyState. */
BOOL DMA_InitKeyboard(void);
BOOL DMA_IsKeyboardReady(void);
void DMA_ResetKeyboard(void);  /* resets init state so next attach retries */
BOOL DMA_IsKeyDown(UINT32 vk);
BOOL DMA_IsKeyPressed(UINT32 vk);
BOOL DMA_IsKeyReleased(UINT32 vk);

/* ── State accessors ────────────────────────────────────────────────────── */
UINT64 DMA_GetCR3(void);   /* PID as UINT64 — non-zero = attached */
UINT64 DMA_GetBase(void);
UINT64 DMA_GetPEB(void);
DWORD  DMA_GetPID(void);
BOOL   DMA_IsAttached(void);
BOOL   DMA_Reattach(void); /* re-resolve PID+base after game restart */

/* AOB scan logger base (defined in dma_mem.cpp) */
extern UINT64 g_aobLogBase;

#ifdef __cplusplus
}
#endif
