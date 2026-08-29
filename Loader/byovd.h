#pragma once

#ifdef SERAPH_DMA_BUILD
#include "../DMA/byovd.h"
#else

#include <windows.h>
#define BYOVD_IsKeyDown(vk)     ((GetAsyncKeyState((int)(vk)) & 0x8000) != 0)
#define BYOVD_IsKeyPressed(vk)  ((GetAsyncKeyState((int)(vk)) & 0x8000) != 0)
#define BYOVD_IsKeyReleased(vk) ((GetAsyncKeyState((int)(vk)) & 0x8001) == 1)
#ifdef __cplusplus
extern "C" {
#endif

/* Set the payload context before initialization for callbacks */
struct PayloadCtx;
void BYOVD_SetInitCtx(const struct PayloadCtx* ctx);

/* Loads CtiIo64.sys via NtLoadDriver (no SCM, no Event Log), bootstraps CR3 */
BOOL   BYOVD_Init(void);
/* Returns TRUE if driver is open and BYOVD_Init succeeded. Safe to call
 * from any thread at any time — avoids calling BYOVD functions before init. */
BOOL   BYOVD_IsReady(void);
/* Unloads driver, cleans up */
void   BYOVD_Shutdown(void);
/* Walk ActiveProcessLinks to find a process by ImageFileName (char, e.g. "destiny2.exe") */
UINT64 BYOVD_FindProcessCR3(const char *imageName);
/* Walk ActiveProcessLinks to find a process by its process ID (PID) */
UINT64 BYOVD_FindProcessCR3ByPid(DWORD targetPid);
/* Invalidate the FindProcessCR3 name->CR3 cache — call from Attach_Invalidate() so
 * Destiny2ProcessFound() re-walks EPROCESS after the game exits (fixes re-attach). */
void   BYOVD_InvalidateProcessCache(void);
/* Walk ActiveProcessLinks to find process by name, returning CR3 AND PEB virtual address.
 * EP_PEB = 0x550 on Win10 22H2 x64. Returns FALSE if not found. */
BOOL   BYOVD_FindProcessInfo(const char *imageName, UINT64 *outCR3, UINT64 *outPebVA);
/* Read/write process virtual address space via physical memory */
BOOL   BYOVD_ReadVA(UINT64 cr3, UINT64 va, void *buf, ULONG size);
BOOL   BYOVD_ReadVA_NoCache(UINT64 cr3, UINT64 va, void *buf, ULONG size);
BOOL   BYOVD_WriteVA(UINT64 cr3, UINT64 va, const void *buf, ULONG size);
/* Write variant that bypasses the VA->PA LRU cache and forces a fresh page
 * walk for every page touched.  Use for writes targeting pages that may
 * remap underneath us (heap data, dynamic allocations) where a stale cached
 * PA would land the write in unrelated physical memory.  ~5 extra physical
 * reads per page; negligible for small writes.                            */
BOOL   BYOVD_WriteVA_Fresh(UINT64 cr3, UINT64 va, const void *buf, ULONG size);
/* Set the R/W bit in the PTE for `va` so D2 usermode code can write to it.
 * Required for shellcode mailbox slots that live in .text (normally R-X).
 * Caller must hold BYOVD_LOCK. */
BOOL   BYOVD_SetPageWritable(UINT64 cr3, UINT64 va);
/* Walk PEB.Ldr module list physically to get image base */
UINT64 BYOVD_GetModuleBase(UINT64 cr3, UINT64 peb_va, const wchar_t *modName);
/* ── Batch scatter read API ──────────────────────────────────────────────
 * Reads multiple independent VAs with a single BYOVD_LOCK acquisition.
 * Use for structured reads of multiple sparse fields (e.g. SObject entries,
 * TigerList fields, fly.c camera+angles+pos in one lock window).
 * Each entry specifies a target VA, output buffer, and read size.
 * Returns TRUE if ALL reads succeeded.  Caller need NOT hold BYOVD_LOCK. */
typedef struct {
    UINT64 va;
    void  *buf;
    ULONG  size;
} BYOVD_READ_BATCH_ENTRY;
BOOL BYOVD_ReadBatch(UINT64 cr3, BYOVD_READ_BATCH_ENTRY *entries, int count);

/* Scan process VA range for a byte pattern. mask: 0xFF=exact, 0x00=wildcard.
 * scanBase/scanLen define the VA window (e.g. imageBase + 0 to imageBase + 0x6000000).
 * Returns matching VA or 0.
 * NOTE: reads in 256 KB chunks internally for ~64× fewer iterations vs 4 KB pages. */
UINT64 BYOVD_ScanPattern(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                         const UINT8 *pattern, const UINT8 *mask, UINT8 patLen);
UINT64 BYOVD_ScanPatternRaw(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                            const UINT8 *pattern, const UINT8 *mask, UINT8 patLen);
/* Multi-pattern single-pass scan: reads each chunk once, tests all entries.
 * scanLimit: if >0, pattern is only matched within the first scanLimit bytes.
 * result is filled with the first matching VA (0 if not found).
 * Caller MUST hold BYOVD_LOCK. Returns number of patterns found.
 * NOTE: reads in 256 KB chunks internally for ~64× fewer iterations vs 4 KB pages. */
typedef struct {
    const UINT8 *pattern;
    const UINT8 *mask;
    UINT8        patLen;
    UINT64       scanLimit; /* 0 = use full scanLen */
    UINT64       result;    /* output */
} BYOVD_SCAN_ENTRY;
int BYOVD_ScanMultiPattern(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                            BYOVD_SCAN_ENTRY *entries, int count);
/* Resolve PE section bounds for moduleBase (cached per module and occurrence).
 * Returns FALSE if PE parse fails. */
BOOL   BYOVD_GetSectionBounds(UINT64 cr3, UINT64 moduleBase,
                              const char *secName, int occurrence,
                              UINT64 *outVA, UINT64 *outLen);
BOOL   BYOVD_GetTextBounds(UINT64 cr3, UINT64 moduleBase,
                           UINT64 *outVA, UINT64 *outLen);
/* Resolve full PE image bounds for moduleBase (= [base, base+SizeOfImage]).
 * Used by FeatureInitThread for a single whole-module multi-pattern pass —
 * avoids section-bounds parsing failures (which we've seen on some PCs)
 * and is only marginally slower than a section-restricted scan.
 * Returns FALSE if PE parse fails (caller should fall back to a fixed cap). */
BOOL   BYOVD_GetImageBounds(UINT64 cr3, UINT64 moduleBase,
                            UINT64 *outVA, UINT64 *outLen);
/* .text-restricted scanners — wrap the raw scanners and constrain the search
 * to executable code only.  Use these for instruction-pattern AOBs.
 * Use the raw BYOVD_ScanPattern only when targeting .data or other sections. */
UINT64 BYOVD_ScanPatternText(UINT64 cr3, UINT64 moduleBase,
                             const UINT8 *pattern, const UINT8 *mask, UINT8 patLen);
UINT64 BYOVD_ScanPatternTextRaw(UINT64 cr3, UINT64 moduleBase,
                                const UINT8 *pattern, const UINT8 *mask, UINT8 patLen);
int    BYOVD_ScanMultiPatternText(UINT64 cr3, UINT64 moduleBase,
                                  BYOVD_SCAN_ENTRY *entries, int count);
/* .data-restricted scanners — same shape, restricted to initialized data
 * section.  Use for AOBs anchored on data constants (float literals, etc.). */
BOOL   BYOVD_GetDataBounds(UINT64 cr3, UINT64 moduleBase,
                           UINT64 *outVA, UINT64 *outLen);
UINT64 BYOVD_ScanPatternData(UINT64 cr3, UINT64 moduleBase,
                             const UINT8 *pattern, const UINT8 *mask, UINT8 patLen);
int    BYOVD_ScanMultiPatternData(UINT64 cr3, UINT64 moduleBase,
                                  BYOVD_SCAN_ENTRY *entries, int count);
/* Walk ActiveProcessLinks to find OUR process by PID, overwrite EPROCESS.ImageFileName
 * with fakeName (max 15 chars). Caller MUST hold BYOVD_LOCK. */
BOOL   BYOVD_SpoofProcessImageName(const char *fakeName);
/* ── Perfect DKOM Stealth ─────────────────────────────────────────────────
 * BYOVD_DkomStealth: Phase 1 (hide EPROCESS from ActiveProcessLinks, clear
 *   audit/cmdline fields) + Phase 2 (unlink all ETHREADs from ThreadListEntry).
 *   Call after BYOVD_Init succeeds.  Discovers all offsets dynamically at runtime
 *   (runtime EPROCESS scan → ntoskrnl pattern scan → Win10 22H2 hardcoded fallback).
 * BYOVD_DkomHideHandles: Phase 3 — zero the HANDLE_TABLE entry for s_hDev.
 *   Call from BYOVD_Shutdown BEFORE UnloadDriver. After this call s_hDev is
 *   invisible to kernel handle enumeration; SysNtClose(s_hDev) will return
 *   STATUS_INVALID_HANDLE (expected, ignore the error). */
void   BYOVD_DkomStealth(void);
void   BYOVD_DkomHideHandles(void);
/* Diagnostic step code updated during BYOVD_Init — readable from the render thread
 * to show on-screen progress. Numeric code: 0=init,1=fse-ph1,...10=hide-drv.
 * Stealth: avoids string literals in .rdata. */
extern volatile int g_byovdDiagStep;
/* Notification toast (implemented in gui_core.cpp) */
void   BYOVD_FlushPhysCache(void);
void   Overlay_AddNotification(const wchar_t *header, const wchar_t *body);

/* ── AOB scan result logger ────────────────────────────────────────────────
 * Logs ALL AOB scan results automatically to %TEMP%\seraph_aob.log.
 * Format:  FeatureName: +offset (e.g. "RapidFire: +1238473")
 * Negative offsets mean the result is BELOW the base address.
 *
 * USAGE: set g_aobLogBase = d2Base once at startup (in AttachToDestiny2).
 *        Then set g_aobScanTag before each scan call in feature code:
 *          g_aobScanTag = "RapidFire";
 *          matchVA = BYOVD_ScanPatternText(cr3, d2Base, pat, mask, len);
 *          // g_aobScanTag is consumed by the scan function and auto-reset
 *
 * For BYOVD_ScanMultiPattern, set g_aobScanTagPrefix before the call and
 * the scan function appends "["+entry_index+"]" to each logged result.
 *
 * No logging happens if g_aobScanTag is NULL (default).
 * Compiled to no-op in NDEBUG (release) builds.                          */
extern UINT64      g_aobLogBase;     /* base for offset calc (0 = disabled) */
extern const char *g_aobScanTag;     /* tag consumed by next scan call       */
extern const char *g_aobScanTagPrefix; /* prefix for ScanMultiPattern entries */
void BYOVD_LogScanResult(const char *feature, UINT64 resultVA);
/* Convenience: set tag, call scan, log automatically */
#define BYOVD_SCAN_TAG(tag)  do { g_aobScanTag = (tag); } while(0)
#ifdef __cplusplus
}
#endif

#endif /* SERAPH_DMA_BUILD */
