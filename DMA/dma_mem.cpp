/*
 * dma_mem.cpp  --  DMA memory engine implementation via Teeko _DMA (MemProcFS/VMMDLL).
 *
 * Performance choices:
 *   - Pattern scans read 1 MB at a time into a stack/heap buffer and search
 *     locally. This reduces FPGA round-trips from ~12 500 (4 KB pages over
 *     50 MB) to ~50 — a 250x reduction on a typical D2 .text scan.
 *   - Multi-pattern scans read each chunk exactly once and test all patterns
 *     simultaneously — O(1) chunk-reads regardless of pattern count.
 *   - Scatter API maps directly to VMMDLL_Scatter_* so N independent reads
 *     collapse into a single PCIe DMA transaction.
 *   - std::mutex g_dmaLock protects the VMMDLL handle from concurrent calls;
 *     it does NOT need to serialize every individual read (unlike BYOVD where
 *     the driver's mmap cache was stateful and non-reentrant).
 */

#include "dma_mem.hpp"
#include "dma_fixup.h"
#include "dma_dll_loader.h"
#include "debug.h"
#include "../../DMA-Lib-main/Teeko-DMA-Lib-main/Teeko-DMA-Lib/Teeko-DMA-Lib/Teeko-DMA/DMA.hpp"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <algorithm>

/* ============================================================
 *  Global lock + C-compatible wrappers
 * ============================================================ */
std::mutex g_dmaLock;

/* Global diagnostic string for GUI loading screen */
extern "C" volatile const char *g_byovdDiagStep = "DMA Engine Active";

/* AOB scan result logger base — set to d2Base in dma_attach.cpp.
 * Defined here for link consistency with features that #include "byovd.h". */
UINT64 g_aobLogBase = 0;

/* C wrappers so .c feature files can call DMA_LOCK()/DMA_UNLOCK()
 * without including C++ headers.  dma_mem.hpp defines the macros
 * to call these when compiled as C. */
extern "C" void DMA_LockAcquire(void)     { g_dmaLock.lock();         }
extern "C" void DMA_LockRelease(void)     { g_dmaLock.unlock();       }
extern "C" BOOL DMA_LockTryAcquire(void)  { return g_dmaLock.try_lock() ? TRUE : FALSE; }

/* ============================================================
 *  Internal cached state
 * ============================================================ */
static DWORD  s_pid    = 0;
static UINT64 s_base   = 0;
static UINT64 s_peb    = 0;
static UINT64 s_cr3    = 0;   /* PID cast to UINT64 */

/* Per-module section bounds (parsed once, cached forever until detach) */
struct SecCache {
    UINT64 mod;
    UINT64 textVA, textLen;
    UINT64 dataVA, dataLen;
    UINT64 imgVA,  imgLen;
};
static SecCache s_sec[8];
static int      s_secN = 0;

/* ============================================================
 *  Section-bounds parsing  (reads PE headers via DMA)
 * ============================================================ */
static bool ParseSections(UINT64 mod, SecCache &out) {
    auto &d = _DMA::Get();
    LONG elfanew = 0;
    if (!d.ReadRaw(mod + 0x3C, &elfanew, 4) || elfanew < 0 || elfanew > 0x1000)
        return false;

    UINT64 nt = mod + (UINT32)elfanew;
    UINT32 sig = 0;
    if (!d.ReadRaw(nt, &sig, 4) || sig != 0x00004550) return false;

    USHORT nSec = 0, optSz = 0;
    d.ReadRaw(nt + 6,  &nSec,  2);
    d.ReadRaw(nt + 20, &optSz, 2);

    UINT32 imgSz = 0;
    d.ReadRaw(nt + 24 + 0x38, &imgSz, 4);

    out = {};
    out.mod    = mod;
    out.imgVA  = mod;
    out.imgLen = imgSz;

    UINT64 sec0 = nt + 24 + optSz;
    for (USHORT i = 0; i < nSec && i < 96; i++) {
        UINT64 sh = sec0 + (UINT64)i * 40;
        char nm[9] = {};
        d.ReadRaw(sh, nm, 8);
        UINT32 vsz = 0, rva = 0;
        d.ReadRaw(sh + 8,  &vsz, 4);
        d.ReadRaw(sh + 12, &rva, 4);
        if (!rva || !vsz) continue;
        /* D2 splits code across .text, .text$mn, .text$x, .text$di, etc.
         * Merge ALL .text* sections into one range so patterns in any
         * subsection are found by ScanPatternText / ScanMultiPatternText. */
        if (!memcmp(nm, ".text", 5)) {
            UINT64 secEnd = mod + rva + vsz;
            if (!out.textVA) {
                out.textVA = mod + rva;
                out.textLen = vsz;
            } else {
                UINT64 thisEnd = out.textVA + out.textLen;
                UINT64 newEnd  = mod + rva + vsz;
                if (mod + rva < out.textVA) out.textVA = mod + rva;
                if (newEnd > thisEnd) out.textLen = (UINT32)(newEnd - out.textVA);
            }
        }
        /* D2 also splits .rdata across .rdata$brc, .rdata$zzzdbg, .rdata$r, etc.
         * Merge ALL .rdata* sections into one range so float constants in any
         * subsection are found by ScanPatternData / ScanMultiPatternData. */
        if (!memcmp(nm, ".rdata", 6)) {
            if (!out.dataVA) {
                out.dataVA = mod + rva;
                out.dataLen = vsz;
            } else {
                UINT64 thisEnd = out.dataVA + out.dataLen;
                UINT64 newEnd  = mod + rva + vsz;
                if (mod + rva < out.dataVA) out.dataVA = mod + rva;
                if (newEnd > thisEnd) out.dataLen = (UINT32)(newEnd - out.dataVA);
            }
        }
        /* .data section — fallback if no .rdata found */
        if (!memcmp(nm, ".data", 5) && !out.dataVA)
                                      { out.dataVA = mod+rva; out.dataLen = vsz; }
    }
    return out.textVA != 0;
}

static SecCache *GetSec(UINT64 mod) {
    for (int i = 0; i < s_secN; i++) if (s_sec[i].mod == mod) return &s_sec[i];
    if (s_secN >= 8) return nullptr;
    if (!ParseSections(mod, s_sec[s_secN])) return nullptr;
    return &s_sec[s_secN++];
}

/* ============================================================
 *  Core scan — reads CHUNK_SIZE at a time (1 MB), scans locally.
 *  All pattern matching in CPU cache — much faster than page-by-page DMA.
 * ============================================================ */
/* DMA scan chunk: 32 MB per call instead of 1 MB.
 * Reduces MemProcFS round-trips from ~500 to ~16 for a 500 MB D2 image.
 * No NOCACHE — MemProcFS cache is fine for AOB scans (module doesn’t change). */
static constexpr UINT32 SCAN_CHUNK = 32u << 20; /* 32 MB per DMA read */

/* Read a scan chunk with zero-padding for unreadable pages.
 * No NOCACHE — the MemProcFS cache makes repeated scans and the first
 * large scatter much faster; AOBs in a running game don’t change. */
static void ScanRead(VMM_HANDLE h, DWORD pid, UINT64 va, UINT8 *buf, UINT32 size) {
    if (!h || !pid) { memset(buf, 0, size); return; }
    DWORD br = 0;
    if (!VMMDLL_MemReadEx(h, pid, va, buf, size, &br,
                          VMMDLL_FLAG_ZEROPAD_ON_FAIL))
        memset(buf, 0, size);
}

static void ZeroOutPatternInRAM(const UINT8 *pattern, const UINT8 *mask, UINT8 patLen) {
    if (!pattern || !mask || !patLen) return;
    UINT8 *pPattern = (UINT8*)pattern;
    UINT8 *pMask = (UINT8*)mask;
    DWORD oldProtect1 = 0, oldProtect2 = 0;
    if (VirtualProtect(pPattern, patLen, PAGE_READWRITE, &oldProtect1)) {
        SecureZeroMemory(pPattern, patLen);
        VirtualProtect(pPattern, patLen, oldProtect1, &oldProtect1);
    }
    if (VirtualProtect(pMask, patLen, PAGE_READWRITE, &oldProtect2)) {
        SecureZeroMemory(pMask, patLen);
        VirtualProtect(pMask, patLen, oldProtect2, &oldProtect2);
    }
}

#include "../Loader/xor_strings.h"

#ifndef SERAPH_KEY1
#define SERAPH_KEY1 0x12345678u
#define SERAPH_KEY2 0x87654321u
#define SERAPH_KEY3 0x11223344u
#define SERAPH_KEY4 0x55667788u
#endif

static inline void decrypt_aob(const UINT8 *src, UINT8 *dst, int len) {
    if (!src || !dst || len <= 0) return;
    for (int i = 0; i < len; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        UINT8 kb = (UINT8)(v3 & 0xFF);
        dst[i] = src[i] ^ kb;
    }
}

#include <memory>

static std::vector<UINT8> g_textCache;
static UINT64             g_textCacheVA = 0;
static UINT64             g_textCacheLen = 0;
static DWORD              g_textCachePID = 0;
static BOOL               g_textCacheValid = FALSE;

static BOOL EnsureTextCache(UINT64 cr3, UINT64 modBase) {
    auto &d = _DMA::Get();
    DWORD pid = d.GetPID();
    if (!pid) return FALSE;
    VMM_HANDLE h = d.GetVMM();
    if (!h) return FALSE;

    UINT64 textVA = 0, textLen = 0;
    if (!DMA_GetTextBounds(cr3, modBase, &textVA, &textLen))
        return FALSE;

    if (g_textCacheValid && g_textCachePID == pid && g_textCacheVA == textVA && g_textCacheLen == textLen)
        return TRUE;

    // Cache miss or invalid - load it!
    g_textCacheValid = FALSE;
    g_textCache.resize(textLen);
    g_textCacheVA = textVA;
    g_textCacheLen = textLen;
    g_textCachePID = pid;

    // Read the entire .text section in chunks of 32MB
    for (UINT64 off = 0; off < textLen; ) {
        UINT32 chunk = (UINT32)(std::min)((UINT64)SCAN_CHUNK, textLen - off);
        ScanRead(h, pid, textVA + off, g_textCache.data() + off, chunk);
        off += chunk;
    }

    g_textCacheValid = TRUE;
    return TRUE;
}

static UINT64 ScanBuf(UINT64 base, UINT64 len,
                       const UINT8 *pat, const UINT8 *mask, UINT8 plen)
{
    if (!plen || !pat || !mask || !len) return 0;
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();

    UINT8 dec_pat[256];
    UINT8 dec_mask[256];
    const UINT8 *p_pat = pat;
    const UINT8 *p_mask = mask;
    if (plen <= 256) {
        decrypt_aob(pat, dec_pat, plen);
        decrypt_aob(mask, dec_mask, plen);
        p_pat = dec_pat;
        p_mask = dec_mask;
    }

    // Find the first non-wildcard byte to use with memchr
    UINT8 firstIdx = 0;
    while (firstIdx < plen && !p_mask[firstIdx]) {
        firstIdx++;
    }

    const UINT32 overlap = (plen > 1) ? (UINT32)(plen - 1) : 0;
    // Allocate raw memory without zero-initialization to avoid cache dirt/overhead
    std::unique_ptr<UINT8[]> buf(new UINT8[SCAN_CHUNK + overlap]);
    UINT32 tail = 0;

    for (UINT64 off = 0; off < len; ) {
        UINT32 chunk = (UINT32)(std::min)((UINT64)SCAN_CHUNK, len - off);
        ScanRead(h, s_pid, base + off, buf.get() + tail, chunk);

        const UINT32 scanLen = tail + chunk;

        if (firstIdx < plen) {
            UINT8 firstByte = p_pat[firstIdx];
            UINT32 searchLimit = scanLen - (plen - 1 - firstIdx);
            for (UINT32 i = firstIdx; i < searchLimit; ) {
                const void* match = memchr(buf.get() + i, firstByte, searchLimit - i);
                if (!match) break;

                i = (UINT32)((const UINT8*)match - buf.get());

                bool ok = true;
                for (UINT8 j = 0; j < plen; j++) {
                    if (j == firstIdx) continue;
                    if (p_mask[j] && buf[i - firstIdx + j] != p_pat[j]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    ZeroOutPatternInRAM(pat, mask, plen);
                    return base + off - tail + (i - firstIdx);
                }
                i++;
            }
        } else {
            // All-wildcard fallback
            for (UINT32 i = 0; i + plen <= scanLen; i++) {
                ZeroOutPatternInRAM(pat, mask, plen);
                return base + off - tail + i;
            }
        }

        if (overlap > 0 && scanLen > 0) {
            tail = (scanLen < overlap) ? scanLen : overlap;
            memmove(buf.get(), buf.get() + scanLen - tail, tail);
        } else {
            tail = 0;
        }
        off += chunk;
    }
    return 0;
}

/* Multi-pattern: read each chunk once, test all patterns (overlap carry like ScanBuf).
 * Optimizations:
 *   1. Allocation: Raw allocation without zero-initialization.
 *   2. Cache Locality: Single linear sweep over chunk memory checking all patterns concurrently (loop-interchange).
 *   3. Filter: Instantly skips mismatches on the first non-wildcard byte. */
static int ScanBufMulti(UINT64 base, UINT64 len,
                         DMA_SCAN_ENTRY *entries, int cnt)
{
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    int found = 0;

    if (cnt > 128) cnt = 128;

    UINT8 maxPl = 0;
    for (int e = 0; e < cnt; e++)
        if (entries[e].patLen > maxPl) maxPl = entries[e].patLen;
    const UINT32 overlap = (maxPl > 1) ? (UINT32)(maxPl - 1) : 0;

    std::unique_ptr<UINT8[]> buf(new UINT8[SCAN_CHUNK + overlap]);
    UINT32 tail = 0;

    UINT8 dec_pats[128][256];
    UINT8 dec_masks[128][256];
    const UINT8 *p_pats[128];
    const UINT8 *p_masks[128];

    UINT8 firstIdx[128];
    UINT8 firstByte[128];

    for (int e = 0; e < cnt; e++) {
        p_pats[e] = entries[e].pattern;
        p_masks[e] = entries[e].mask;
        UINT8 pl = entries[e].patLen;

        firstIdx[e] = 0;
        firstByte[e] = 0;

        if (pl && pl <= 256 && e < 128) {
            decrypt_aob(entries[e].pattern, dec_pats[e], pl);
            decrypt_aob(entries[e].mask, dec_masks[e], pl);
            p_pats[e] = dec_pats[e];
            p_masks[e] = dec_masks[e];

            while (firstIdx[e] < pl && !p_masks[e][firstIdx[e]]) {
                firstIdx[e]++;
            }
            if (firstIdx[e] < pl) {
                firstByte[e] = p_pats[e][firstIdx[e]];
            }
        }
    }

    for (UINT64 off = 0; off < len; ) {
        UINT32 chunk = (UINT32)(std::min)((UINT64)SCAN_CHUNK, len - off);
        ScanRead(h, s_pid, base + off, buf.get() + tail, chunk);

        const UINT32 scanLen = tail + chunk;

        // Perform a single pass cache-friendly sweep of the chunk
        for (UINT32 i = 0; i < scanLen; i++) {
            UINT8 b = buf[i];
            for (int e = 0; e < cnt; e++) {
                if (entries[e].result) continue;
                UINT8 pl = entries[e].patLen;
                if (!pl || e >= 128) continue;

                UINT8 idx = firstIdx[e];
                if (idx >= pl) {
                    // All wildcards
                    UINT64 absBase = base + off - tail;
                    entries[e].result = absBase + i;
                    ZeroOutPatternInRAM(entries[e].pattern, entries[e].mask, pl);
                    found++;
                    continue;
                }

                // Fast filter mismatch
                if (b != firstByte[e]) continue;

                INT32 startPos = (INT32)i - idx;
                if (startPos < 0) continue;

                UINT64 absBase = base + off - tail;
                UINT64 absLimit = entries[e].scanLimit ? (base + entries[e].scanLimit) : (base + len);
                if (absBase + startPos + pl > absLimit) continue;
                if (startPos + pl > scanLen) continue;

                bool ok = true;
                for (UINT8 j = 0; j < pl; j++) {
                    if (j == idx) continue;
                    if (p_masks[e][j] && buf[startPos + j] != p_pats[e][j]) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    entries[e].result = absBase + startPos;
                    ZeroOutPatternInRAM(entries[e].pattern, entries[e].mask, pl);
                    found++;
                }
            }
        }

        bool all = true;
        for (int e = 0; e < cnt; e++) {
            if (entries[e].patLen && !entries[e].result) { all = false; break; }
        }
        if (all) break;

        if (overlap > 0 && scanLen > 0) {
            tail = (scanLen < overlap) ? scanLen : overlap;
            memmove(buf.get(), buf.get() + scanLen - tail, tail);
        } else {
            tail = 0;
        }
        off += chunk;
    }
    return found;
}

/* ============================================================
 *  Init / Shutdown
 * ============================================================ */
#include <time.h>

extern "C" BOOL DMA_Init(void) {
    srand((unsigned)time(NULL));
    DmaLoader_EnsureSearchPath();
    g_byovdDiagStep = "mmap";
    DmaEnsureMemoryMap();
    auto &d = _DMA::Get();
    g_byovdDiagStep = "fpga";
    if (!d.Initialize(/*memMap=*/true)) {
        if (!d.Initialize(/*memMap=*/false))
            return FALSE;
    }
    DmaSetFPGA(d.GetVMM());
    return TRUE;
}

extern "C" void DMA_Shutdown(void) {
    _DMA::Get().Disconnect();
    s_pid = 0; s_base = 0; s_peb = 0; s_cr3 = 0;
    s_secN = 0;
    g_textCacheValid = FALSE;
    g_textCache.clear();
    g_textCacheVA = 0;
    g_textCacheLen = 0;
    g_textCachePID = 0;
}

/* ============================================================
 *  Process discovery (Vanish: VMMDLL_PidGetFromName — never Attach for polls)
 * ============================================================ */
static DWORD DmaPidFromName(const char *name) {
    if (!name || !name[0]) return 0;
    VMM_HANDLE h = _DMA::Get().GetVMM();
    if (!h) return 0;
    DWORD pid = 0;
    if (!VMMDLL_PidGetFromName(h, (LPSTR)name, &pid) || !pid)
        return 0;
    return pid;
}

extern "C" BOOL DMA_ProcessExists(const char *name) {
    return DmaPidFromName(name) != 0;
}

extern "C" UINT64 DMA_FindProcessCR3(const char *name) {
    return (UINT64)DmaPidFromName(name);
}

extern "C" BOOL DMA_FindProcessInfo(const char *name, UINT64 *cr3out, UINT64 *pebOut) {
    if (!name || !cr3out || !pebOut) return FALSE;
    auto &d = _DMA::Get();
    if (!d.GetPID() && !d.Attach(name)) return FALSE;
    
    DWORD pid = d.GetPID();
    if (!pid) return FALSE;
    
    *cr3out = (UINT64)pid;
    *pebOut = 0;
    VMM_HANDLE h = d.GetVMM();
    if (h) {
        VMMDLL_PROCESS_INFORMATION pi{};
        pi.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
        pi.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
        SIZE_T cb = sizeof(pi);
        if (VMMDLL_ProcessGetInformation(h, pid, &pi, &cb))
            *pebOut = pi.win.vaPEB;
    }
    s_pid = pid;
    s_cr3 = (UINT64)pid;
    s_base = d.GetMainBase();
    return TRUE;
}

extern "C" void DMA_InvalidateProcessCache(void) {
    s_pid = 0; s_base = 0; s_peb = 0; s_cr3 = 0;
    s_secN = 0;
    auto &d = _DMA::Get();
    d.DetachProcess();
    d.ClearCache();
}

extern "C" void DMA_FlushPhysCache(void) {
    _DMA::Get().ClearCache();
}

extern "C" BOOL DMA_SpoofProcessImageName(const char *) { return TRUE; /* no-op */ }

/* Returns TRUE if va has a valid physical frame in the current process.
 * Used by CaveFinder to skip caves in zero-padded (not-in-RAM) pages. */
extern "C" BOOL DMA_HasPhysFrame(UINT64 va) {
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    DWORD pid = d.GetPID();
    if (!h || !pid || !va) return FALSE;
    UINT64 pa = 0;
    return VMMDLL_MemVirt2Phys(h, pid, va, &pa) && (pa != 0) ? TRUE : FALSE;
}

/* Read with ZEROPAD but without NOCACHE — for cave finding.
 * Pages not in RAM are zero-filled; the caller checks PA before using the result. */
extern "C" BOOL DMA_ReadVAPad(UINT64 va, void *buf, ULONG sz) {
    if (!va || !buf || !sz) return FALSE;
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    DWORD pid = d.GetPID();
    if (!h || !pid) return FALSE;
    DWORD br = 0;
    VMMDLL_MemReadEx(h, pid, va, (PBYTE)buf, sz, &br, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
    return TRUE; /* always succeeds with ZEROPAD */
}

/* Cached read — no NOCACHE, no ZEROPAD.  Uses MemProcFS internal cache.
 * The batch AOB scan populates the cache; the cave scan (which runs after)
 * hits cached pages and finds real 0xCC runs without needing a hardware read.
 * Fails for pages that were never scanned (not in cache, not in RAM). */
extern "C" BOOL DMA_ReadVACached(UINT64 va, void *buf, ULONG sz) {
    if (!va || !buf || !sz) return FALSE;
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    DWORD pid = d.GetPID();
    if (!h || !pid) return FALSE;
    DWORD br = 0;
    return VMMDLL_MemReadEx(h, pid, va, (PBYTE)buf, sz, &br, 0) ? TRUE : FALSE;
}

/* ============================================================
 *  Read / Write  — direct, no serialization needed per call.
 *  Lock is held at the feature level when needed.
 * ============================================================ */
extern "C" BOOL DMA_ReadVA(UINT64 cr3, UINT64 va, void *buf, ULONG sz) {
    if (!va || !buf || !sz) return FALSE;
    auto &d = _DMA::Get();
    if (!d.GetPID()) return FALSE;
    return d.ReadRaw(va, buf, sz) ? TRUE : FALSE;
}

/* WriteVA via virtual address (works for .data / heap). */
extern "C" BOOL DMA_WriteVA(UINT64 cr3, UINT64 va, const void *buf, ULONG sz) {
    if (!va || !buf || !sz) return FALSE;
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    DWORD pid = d.GetPID();
    if (!h || !pid) return FALSE;
    return VMMDLL_MemWrite(h, pid, va, (PBYTE)buf, (DWORD)sz) ? TRUE : FALSE;
}

/* ── Page table walk helper: read a physical page-table entry ────────────
 * Uses VMMDLL_MemWrite with dwPID=(DWORD)-1 to read physical memory
 * directly, bypassing process virtual address space entirely. */
static BOOL DMA_ReadPhys(UINT64 pa, void *buf, ULONG sz) {
    VMM_HANDLE h = _DMA::Get().GetVMM();
    if (!h) return FALSE;
    DWORD br = 0;
    return VMMDLL_MemReadEx(h, (DWORD)-1, pa, (PBYTE)buf, sz, &br,
                            VMMDLL_FLAG_NOCACHE) ? TRUE : FALSE;
}

/* ── SetPageWritable: walk x64 page tables to set the R/W bit (bit 1)
 * on the PTE for the given virtual address.  Required so the game's CPU
 * can write to the mailbox slot inside a .text code cave hook.
 *
 * Walk: PML4 → PDPT → PD → PT, each level index = (va >> shift) & 0x1FF.
 * On DMA we read/write physical page-table memory directly (dwPID=-1),
 * bypassing any virtual-address write restrictions.
 *
 * Returns TRUE if the PTE was found and its R/W bit is now set. */
extern "C" BOOL DMA_SetPageWritable(UINT64 va) {
    if (!va) return FALSE;
    auto &d = _DMA::Get();
    DWORD pid = d.GetPID();
    if (!pid) return FALSE;
    VMM_HANDLE h = d.GetVMM();
    if (!h) return FALSE;

    /* 1. Read the target process's CR3 (physical address of PML4 table).
     *    VMMDLL_ProcessGetInformation returns paDTB (page directory table base). */
    UINT64 pml4Phys = 0;
    {
        VMMDLL_PROCESS_INFORMATION pi{};
        pi.magic    = VMMDLL_PROCESS_INFORMATION_MAGIC;
        pi.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
        SIZE_T cb   = sizeof(pi);
        if (!VMMDLL_ProcessGetInformation(h, pid, &pi, &cb))
            return FALSE;
        pml4Phys = pi.paDTB; /* CR3 value = PML4 physical address */
    }
    if (!pml4Phys || (pml4Phys & 0xFFF)) /* must be 4KB-aligned */
        return FALSE;

    /* 2. Walk the 4-level page tables */
    const int levels[] = { 39, 30, 21, 12 }; /* shift amounts */
    UINT64 tblPhys = pml4Phys;

    for (int li = 0; li < 4; li++) {
        int idx = (int)((va >> levels[li]) & 0x1FF);
        UINT64 entry = 0;

        if (!DMA_ReadPhys(tblPhys + (UINT64)idx * 8, &entry, 8))
            return FALSE;

        /* Check Present bit (bit 0) */
        if (!(entry & 1))
            return FALSE;

        if (li == 3) {
            /* ── Leaf PTE: set the R/W bit (bit 1) ── */
            UINT64 ptePhys = tblPhys + (UINT64)idx * 8;

            /* If the large-page flag (bit 7) is set, this is a 2MB or 1GB
             * page — the PTE at this level IS the final mapping.  We can
             * still set R/W on it. */
            if (entry & 0x80) /* PS = large page */
                return FALSE; /* skip large pages, shouldn't happen for .text */

            /* Set R/W bit */
            UINT64 newEntry = entry | 2;
            if (newEntry == entry)
                return TRUE; /* already writable */

            /* Write the modified PTE back via physical write */
            if (!VMMDLL_MemWrite(h, (DWORD)-1, ptePhys,
                                 (PBYTE)&newEntry, 8))
                return FALSE;

            /* Flush TLB on the target CPU is not strictly needed for DMA
             * (the CPU re-fetches from page tables on next access), but
             * MemProcFS may cache PTEs.  Clear its cache to be safe. */
            d.ClearCache();
            return TRUE;
        }

        /* ── Non-leaf: extract next table physical address ── */
        /* Bits 12..51 form the page-frame number (PFN).  Mask off
         * attribute bits (0-11) to get the physical address of the
         * next-level table. */
        tblPhys = entry & 0x0000FFFFFFF000ULL;
        if (!tblPhys)
            return FALSE;
    }

    return FALSE; /* should not reach here */
}

extern "C" BOOL DMA_RestorePageReadOnly(UINT64 va) {
    if (!va) return FALSE;
    auto &d = _DMA::Get();
    DWORD pid = d.GetPID();
    if (!pid) return FALSE;
    VMM_HANDLE h = d.GetVMM();
    if (!h) return FALSE;

    UINT64 pml4Phys = 0;
    {
        VMMDLL_PROCESS_INFORMATION pi{};
        pi.magic    = VMMDLL_PROCESS_INFORMATION_MAGIC;
        pi.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
        SIZE_T cb   = sizeof(pi);
        if (!VMMDLL_ProcessGetInformation(h, pid, &pi, &cb))
            return FALSE;
        pml4Phys = pi.paDTB;
    }
    if (!pml4Phys || (pml4Phys & 0xFFF))
        return FALSE;

    const int levels[] = { 39, 30, 21, 12 };
    UINT64 tblPhys = pml4Phys;

    for (int li = 0; li < 4; li++) {
        int idx = (int)((va >> levels[li]) & 0x1FF);
        UINT64 entry = 0;

        if (!DMA_ReadPhys(tblPhys + (UINT64)idx * 8, &entry, 8))
            return FALSE;

        if (!(entry & 1))
            return FALSE;

        if (li == 3) {
            UINT64 ptePhys = tblPhys + (UINT64)idx * 8;
            if (entry & 0x80)
                return FALSE;

            UINT64 newEntry = entry & ~2ULL;
            if (newEntry == entry)
                return TRUE;

            if (!VMMDLL_MemWrite(h, (DWORD)-1, ptePhys, (PBYTE)&newEntry, 8))
                return FALSE;

            d.ClearCache();
            return TRUE;
        }

        tblPhys = entry & 0x0000FFFFFFF000ULL;
        if (!tblPhys)
            return FALSE;
    }
    return FALSE;
}

/* WriteVA via physical address — translates VA->PA first, then writes
 * with dwPID=(DWORD)-1 (raw physical write, bypasses all software state).
 * Required for .text cave / hook writes where VMMDLL_MemWrite by VA may
 * fail due to large-page PTEs or transient page-table states. */
extern "C" BOOL DMA_WriteVAPhys(UINT64 va, const void *buf, ULONG sz) {
    if (!va || !buf || !sz) return FALSE;
    auto &d = _DMA::Get();
    VMM_HANDLE h = d.GetVMM();
    DWORD pid = d.GetPID();
    if (!h || !pid) return FALSE;

    /* Write page by page because VA->PA translation is per 4KB page. */
    const UINT8 *src = (const UINT8 *)buf;
    ULONG remaining = sz;
    UINT64 curVA = va;

    while (remaining > 0) {
        /* Bytes until the next 4KB page boundary (must calculate first). */
        ULONG pageOff = (ULONG)(curVA & 0xFFF);
        ULONG chunk   = 0x1000 - pageOff;
        if (chunk > remaining) chunk = remaining;

        UINT64 pa = 0;
        if (!VMMDLL_MemVirt2Phys(h, pid, curVA, &pa) || !pa) {
            /* PA not available — fall back to virtual write for this page. */
            (void)VMMDLL_MemWrite(h, pid, curVA, (PBYTE)src, chunk);
            src += chunk; curVA += chunk; remaining -= chunk;
            continue;
        }

        if (!VMMDLL_MemWrite(h, (DWORD)-1, pa, (PBYTE)src, chunk)) {
            /* Physical write failed — fall back to virtual write. */
            (void)VMMDLL_MemWrite(h, pid, curVA, (PBYTE)src, chunk);
        }

        src       += chunk;
        curVA     += chunk;
        remaining -= chunk;
    }
    if (g_textCacheValid && va >= g_textCacheVA && va + sz <= g_textCacheVA + g_textCacheLen) {
        memcpy(g_textCache.data() + (va - g_textCacheVA), buf, sz);
    }
    return TRUE;
}

/* ============================================================
 *  Scatter API  — N reads in one FPGA transaction
 * ============================================================ */
extern "C" DMA_SCATTER_HANDLE DMA_ScatterBegin(void) {
    auto &d = _DMA::Get();
    VMMDLL_SCATTER_HANDLE h = VMMDLL_Scatter_Initialize(
        d.GetVMM(), d.GetPID(), VMMDLL_FLAG_NOCACHE);
    return (DMA_SCATTER_HANDLE)h;
}

extern "C" BOOL DMA_ScatterAddRead(DMA_SCATTER_HANDLE h, UINT64 va, void *buf, UINT32 sz) {
    if (!h || !va || !buf || !sz) return FALSE;
    return VMMDLL_Scatter_PrepareEx(
        (VMMDLL_SCATTER_HANDLE)h, va, sz, (PBYTE)buf, nullptr) ? TRUE : FALSE;
}

extern "C" BOOL DMA_ScatterExecute(DMA_SCATTER_HANDLE h) {
    if (!h) return FALSE;
    return VMMDLL_Scatter_Execute((VMMDLL_SCATTER_HANDLE)h) ? TRUE : FALSE;
}

extern "C" void DMA_ScatterFree(DMA_SCATTER_HANDLE h) {
    if (h) VMMDLL_Scatter_CloseHandle((VMMDLL_SCATTER_HANDLE)h);
}

extern "C" BOOL DMA_ReadBatch(UINT64 cr3, DMA_READ_BATCH_ENTRY *entries, int count) {
    if (!entries || count <= 0) return FALSE;
    DMA_SCATTER_HANDLE h = DMA_ScatterBegin();
    if (!h) return FALSE;
    for (int i = 0; i < count; i++) {
        if (entries[i].va && entries[i].buf && entries[i].size > 0) {
            DMA_ScatterAddRead(h, entries[i].va, entries[i].buf, entries[i].size);
        }
    }
    BOOL ok = DMA_ScatterExecute(h);
    DMA_ScatterFree(h);
    return ok;
}

/* ============================================================
 *  Module / section helpers
 * ============================================================ */
extern "C" UINT64 DMA_GetModuleBase(UINT64, UINT64, const wchar_t *name) {
    if (!name) return 0;
    char nb[260] = {};
    WideCharToMultiByte(CP_ACP, 0, name, -1, nb, 259, nullptr, nullptr);
    return _DMA::Get().GetModuleBase(nb);
}

extern "C" BOOL DMA_GetTextBounds(UINT64, UINT64 mod, UINT64 *va, UINT64 *len) {
    SecCache *c = GetSec(mod);
    if (!c || !c->textVA) return FALSE;
    *va = c->textVA; *len = c->textLen; return TRUE;
}
extern "C" BOOL DMA_GetImageBounds(UINT64, UINT64 mod, UINT64 *va, UINT64 *len) {
    SecCache *c = GetSec(mod);
    if (!c || !c->imgLen) return FALSE;
    *va = c->imgVA; *len = c->imgLen; return TRUE;
}
extern "C" BOOL DMA_GetDataBounds(UINT64, UINT64 mod, UINT64 *va, UINT64 *len) {
    SecCache *c = GetSec(mod);
    if (!c || !c->dataVA) return FALSE;
    *va = c->dataVA; *len = c->dataLen; return TRUE;
}

/* ============================================================
 *  Pattern scanning
 * ============================================================ */
extern "C" UINT64 DMA_ScanPattern(UINT64, UINT64 base, UINT64 len,
                                   const UINT8 *p, const UINT8 *m, UINT8 pl) {
    return ScanBuf(base, len, p, m, pl);
}
extern "C" UINT64 DMA_ScanPatternText(UINT64 cr3, UINT64 mod,
                                       const UINT8 *p, const UINT8 *m, UINT8 pl) {
    if (!EnsureTextCache(cr3, mod)) return 0;
    
    UINT8 dec_pat[256];
    UINT8 dec_mask[256];
    const UINT8 *p_pat = p;
    const UINT8 *p_mask = m;
    if (pl <= 256) {
        decrypt_aob(p, dec_pat, pl);
        decrypt_aob(m, dec_mask, pl);
        p_pat = dec_pat;
        p_mask = dec_mask;
    }

    UINT8 firstIdx = 0;
    while (firstIdx < pl && !p_mask[firstIdx]) {
        firstIdx++;
    }

    if (firstIdx < pl) {
        UINT8 firstByte = p_pat[firstIdx];
        UINT32 searchLimit = (UINT32)(g_textCacheLen - (pl - 1 - firstIdx));
        for (UINT32 i = firstIdx; i < searchLimit; ) {
            const void* match = memchr(g_textCache.data() + i, firstByte, searchLimit - i);
            if (!match) break;

            i = (UINT32)((const UINT8*)match - g_textCache.data());

            bool ok = true;
            for (UINT8 j = 0; j < pl; j++) {
                if (j == firstIdx) continue;
                if (p_mask[j] && g_textCache[i - firstIdx + j] != p_pat[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                UINT64 foundVA = g_textCacheVA + (i - firstIdx);
                ZeroOutPatternInRAM(p, m, pl);
                return foundVA;
            }
            i++;
        }
    } else {
        if (g_textCacheLen >= pl) {
            ZeroOutPatternInRAM(p, m, pl);
            return g_textCacheVA;
        }
    }
    return 0;
}
extern "C" UINT64 DMA_ScanPatternData(UINT64 cr3, UINT64 mod,
                                       const UINT8 *p, const UINT8 *m, UINT8 pl) {
    UINT64 va = 0, len = 0;
    return DMA_GetDataBounds(cr3, mod, &va, &len) ? ScanBuf(va, len, p, m, pl) : 0;
}

extern "C" int DMA_ScanMultiPattern(UINT64, UINT64 base, UINT64 len,
                                     DMA_SCAN_ENTRY *e, int cnt) {
    return ScanBufMulti(base, len, e, cnt);
}
extern "C" int DMA_ScanMultiPatternText(UINT64 cr3, UINT64 mod,
                                         DMA_SCAN_ENTRY *e, int cnt) {
    if (!EnsureTextCache(cr3, mod)) return 0;

    if (cnt > 128) cnt = 128;

    int found = 0;
    UINT8 dec_pats[128][256];
    UINT8 dec_masks[128][256];
    const UINT8 *p_pats[128];
    const UINT8 *p_masks[128];
    UINT8 firstIdx[128];
    UINT8 firstByte[128];

    for (int i = 0; i < cnt; i++) {
        p_pats[i] = e[i].pattern;
        p_masks[i] = e[i].mask;
        UINT8 pl = e[i].patLen;
        firstIdx[i] = 0;
        firstByte[i] = 0;

        if (pl && pl <= 256 && i < 128) {
            decrypt_aob(e[i].pattern, dec_pats[i], pl);
            decrypt_aob(e[i].mask, dec_masks[i], pl);
            p_pats[i] = dec_pats[i];
            p_masks[i] = dec_masks[i];

            while (firstIdx[i] < pl && !p_masks[i][firstIdx[i]]) {
                firstIdx[i]++;
            }
            if (firstIdx[i] < pl) {
                firstByte[i] = p_pats[i][firstIdx[i]];
            }
        }
    }

    for (UINT32 i = 0; i < g_textCacheLen; i++) {
        UINT8 b = g_textCache[i];
        for (int idx = 0; idx < cnt; idx++) {
            if (e[idx].result) continue;
            UINT8 pl = e[idx].patLen;
            if (!pl || idx >= 128) continue;

            UINT8 fIdx = firstIdx[idx];
            if (fIdx >= pl) {
                e[idx].result = g_textCacheVA + i;
                ZeroOutPatternInRAM(e[idx].pattern, e[idx].mask, pl);
                found++;
                continue;
            }

            if (b != firstByte[idx]) continue;

            INT32 startPos = (INT32)i - fIdx;
            if (startPos < 0) continue;

            UINT64 absLimit = e[idx].scanLimit ? (g_textCacheVA + e[idx].scanLimit) : (g_textCacheVA + g_textCacheLen);
            if (g_textCacheVA + startPos + pl > absLimit) continue;
            if (startPos + pl > g_textCacheLen) continue;

            bool ok = true;
            for (UINT8 j = 0; j < pl; j++) {
                if (j == fIdx) continue;
                if (p_masks[idx][j] && g_textCache[startPos + j] != p_pats[idx][j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                e[idx].result = g_textCacheVA + startPos;
                ZeroOutPatternInRAM(e[idx].pattern, e[idx].mask, pl);
                found++;
            }
        }
    }
    return found;
}
extern "C" int DMA_ScanMultiPatternData(UINT64 cr3, UINT64 mod,
                                         DMA_SCAN_ENTRY *e, int cnt) {
    UINT64 va = 0, len = 0;
    return DMA_GetDataBounds(cr3, mod, &va, &len) ? ScanBufMulti(va, len, e, cnt) : 0;
}

/* ============================================================
 *  Heap-wide pattern scan via VAD enumeration
 *  Enumerates all non-image VAD entries (heap, anonymous, page-file backed)
 *  and scans each committed region.  Use when the target pattern lives in
 *  dynamically allocated memory rather than the D2 PE image sections.
 * ============================================================ */
extern "C" UINT64 DMA_ScanPatternHeap(UINT64 /*cr3*/, const UINT8 *pat, const UINT8 *mask, UINT8 patLen) {
    if (!pat || !mask || !patLen) return 0;
    auto &d = _DMA::Get();
    DWORD pid = s_pid;
    if (!pid) return 0;
    VMM_HANDLE h = d.GetVMM();
    if (!h) return 0;

    PVMMDLL_MAP_VAD pVad = nullptr;
    if (!VMMDLL_Map_GetVad(h, pid, FALSE, &pVad) || !pVad) return 0;

    UINT64 result = 0;
    for (DWORD i = 0; i < pVad->cMap && !result; i++) {
        PVMMDLL_MAP_VADENTRY e = &pVad->pMap[i];
        /* Skip image-backed regions (exe/dll sections already covered by module scan) */
        if (e->fImage) continue;
        UINT64 rangeLen = e->vaEnd - e->vaStart + 1;
        /* Skip reservations > 256 MB — typically large reserved-but-not-committed VA */
        if (rangeLen > 0x10000000ULL) continue;
        result = ScanBuf(e->vaStart, rangeLen, pat, mask, patLen);
    }

    VMMDLL_MemFree(pVad);
    return result;
}

/* ============================================================
 *  DMA Keyboard — reads victim-PC keystrokes via gafAsyncKeyState
 *  over DMA (win32kbase.sys → winlogon/csrss → FPGA).
 *  Initialization is idempotent — safe to call on every re-attach.
 * ============================================================ */
static bool s_kb_inited = false;

extern "C" BOOL DMA_InitKeyboard(void) {
    if (s_kb_inited) return TRUE;
    auto &d = _DMA::Get();
    if (!d.GetVMM()) {
        WriteLogFile("DMA_InitKeyboard: no VMM handle");
        return FALSE;
    }
    /* poll at 4 ms = ~250 Hz — faster poll reduces WASD / hotkey latency.
     * debug=true prints detailed step-by-step to log file via printf redirect. */
    WriteLogFile("DMA_InitKeyboard: starting...");
    BOOL ok = d.InitKeyboard(4, true) ? TRUE : FALSE;
    if (!ok) {
        WriteLogFile("DMA_InitKeyboard FAILED (gafAsyncKeyState not found)");
        /* NOTE: s_kb_inited stays FALSE so AttachToDestiny2 can retry on next attach */
        return FALSE;
    }
    s_kb_inited = true;
    WriteLogFile("DMA_InitKeyboard: OK — victim-PC keyboard active (4ms poll)");
    return TRUE;
}

extern "C" BOOL DMA_IsKeyboardReady(void) {
    return s_kb_inited ? TRUE : FALSE;
}
extern "C" void DMA_ResetKeyboard(void) {
    /* Allows the next AttachToDestiny2 call to retry keyboard init.
     * Called from Attach_Invalidate so a failed init on one session
     * does not permanently block retries in subsequent sessions. */
    s_kb_inited = false;
}

extern "C" BOOL DMA_IsKeyDown(UINT32 vk) {
    if (!s_kb_inited) return FALSE;
    return _DMA::Get().IsKeyDown(vk) ? TRUE : FALSE;
}
extern "C" BOOL DMA_IsKeyPressed(UINT32 vk) {
    if (!s_kb_inited) return FALSE;
    return _DMA::Get().IsKeyPressed(vk) ? TRUE : FALSE;
}
extern "C" BOOL DMA_IsKeyReleased(UINT32 vk) {
    if (!s_kb_inited) return FALSE;
    return _DMA::Get().IsKeyReleased(vk) ? TRUE : FALSE;
}

/* ── State accessors ────────────────────────────────────────────────────── */
extern "C" UINT64 DMA_GetCR3(void)    { return s_cr3;  }
extern "C" UINT64 DMA_GetBase(void)   { return s_base; }
extern "C" UINT64 DMA_GetPEB(void)    { return s_peb;  }
extern "C" DWORD  DMA_GetPID(void)    { return s_pid;  }
extern "C" BOOL   DMA_IsAttached(void){ return (s_cr3 && s_base) ? TRUE : FALSE; }

static void DmaDecodeD2Name(char *name, int cap) {
    static const char e[] = {
        0x2F,0x2E,0x38,0x3F,0x22,0x25,0x32,0x79,
        0x65,0x2E,0x33,0x2E,0x00
    };
    for (int i = 0; i < 12 && i < cap - 1; i++) name[i] = e[i] ^ 0x4B;
    name[12] = 0;
}

extern "C" BOOL DMA_Reattach(void) {
    auto &d = _DMA::Get();
    char name[14] = {};
    DmaDecodeD2Name(name, 14);

    if (!d.GetVMM()) {
        s_pid = 0; s_base = 0; s_peb = 0; s_cr3 = 0;
        return FALSE;
    }

    if (!d.Attach(name)) {
        s_pid = 0; s_base = 0; s_peb = 0; s_cr3 = 0;
        return FALSE;
    }

    s_pid  = d.GetPID();
    s_base = d.GetMainBase();
    s_cr3  = (UINT64)s_pid;
    s_secN = 0;

    VMM_HANDLE h = d.GetVMM();
    if (h && s_pid) {
        VMMDLL_PROCESS_INFORMATION pi{};
        pi.magic    = VMMDLL_PROCESS_INFORMATION_MAGIC;
        pi.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
        SIZE_T cb   = sizeof(pi);
        if (VMMDLL_ProcessGetInformation(h, s_pid, &pi, &cb))
            s_peb = pi.win.vaPEB;
    }

    /* Vanish-style: reject attach if module base does not look like a valid PE. */
    if (!s_base) {
        s_cr3 = 0;
        return FALSE;
    }
    {
        UINT16 mz = 0;
        if (!d.ReadRaw(s_base, &mz, sizeof(mz)) || mz != 0x5A4D) {
            s_pid = 0;
            s_base = 0;
            s_peb = 0;
            s_cr3 = 0;
            return FALSE;
        }
    }
    return TRUE;
}

extern "C" BOOL DMA_GetSectionBounds(UINT64, UINT64 mod, const char *name, int occurrence, UINT64 *va, UINT64 *len) {
    if (!name || !va || !len) return FALSE;
    SecCache *c = GetSec(mod);
    if (!c) return FALSE;

    if (strcmp(name, ".text") == 0) {
        if (occurrence == 0) {
            *va = c->textVA; *len = c->textLen; return TRUE;
        }
        return FALSE;
    }
    if (strcmp(name, ".data") == 0 || strcmp(name, ".rdata") == 0) {
        if (occurrence == 0) {
            *va = c->dataVA; *len = c->dataLen; return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}
