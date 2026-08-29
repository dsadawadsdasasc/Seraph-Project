#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LAZYHOOK_MAX         16
#define LAZYHOOK_MAX_STOLEN  32

/* ── Hook entry (internal, but exposed for inspection) ──────────────────── */
typedef struct {
    UINT64 hookVA;                          /* where the JMP is written      */
    UINT64 caveVA;                          /* start of cave code            */
    UINT32 caveUsed;                        /* total bytes written to cave   */
    UINT8  originalBytes[LAZYHOOK_MAX_STOLEN]; /* saved bytes from hookVA    */
    UINT8  stolenLen;                       /* bytes overwritten at hookVA   */
    BOOL   installed;
} LazyHookEntry;

/* ── Install a lazyhook ─────────────────────────────────────────────────────
 *
 *  hookVA     — address in target process to overwrite with JMP
 *  stolenLen  — number of original instruction bytes to overwrite (>= 5)
 *               MUST land on an instruction boundary.
 *               Stolen bytes MUST be position-independent (no RIP-relative).
 *  shellcode  — user-provided code blob executed BEFORE the stolen bytes.
 *               Typically: push regs, do work, pop regs.
 *  shellcodeLen — size of shellcode in bytes.
 *  caveVA     — address of a CC-padding cave (from CaveFinder).
 *               Must have room for: shellcodeLen + stolenLen + 5 (JMP back).
 *
 *  Cave layout after install:
 *    [caveVA + 0]                  → shellcode
 *    [caveVA + shellcodeLen]       → stolen original bytes (copied from hookVA)
 *    [caveVA + shellcodeLen + stolenLen] → E9 rel32 JMP back to hookVA+stolenLen
 *
 *  Hook point after install:
 *    [hookVA + 0]          → E9 rel32 JMP to caveVA
 *    [hookVA + 5 .. stolenLen-1] → multi-byte NOPs (0F 1F ...)
 *
 *  Returns hook ID (>= 0) on success, -1 on failure.
 */
int LazyHook_Install(UINT64 cr3,
                     UINT64 hookVA, UINT8 stolenLen,
                     const UINT8 *shellcode, UINT32 shellcodeLen,
                     UINT64 caveVA);

/* Remove a hook: restores original bytes at hookVA, fills cave with CC.
 * Returns TRUE on success. */
BOOL LazyHook_Remove(int hookId, UINT64 cr3);

/* Remove all installed hooks (call on shutdown). */
void LazyHook_RemoveAll(UINT64 cr3);

/* Get the hook entry for inspection (NULL if invalid). */
const LazyHookEntry *LazyHook_Get(int hookId);

/* Total installed hooks. */
int LazyHook_Count(void);

/* Reset hook table internally without making driver writes (call on process detach/wipe). */
void LazyHook_ResetLocalState(void);

#ifdef __cplusplus
}
#endif
