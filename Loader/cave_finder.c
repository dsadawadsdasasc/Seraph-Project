
#include "cave_finder.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "debug.h"
#include "ThemidaSDK.h"
#include <string.h>

/* ── PE header parsing helpers (read via BYOVD physical memory) ────────── */

static BOOL GetTextSection(UINT64 cr3, UINT64 moduleBase,
                           UINT32 *outRVA, UINT32 *outSize)
{
    DEBUG_CAVE("GetTextSection: moduleBase=0x%I64X cr3=0x%I64X", moduleBase, cr3);

    /* DOS header: e_lfanew at offset 0x3C */
    LONG e_lfanew = 0;
    BYOVD_LOCK();
    BOOL rdDos = BYOVD_ReadVA(cr3, moduleBase + 0x3C, &e_lfanew, 4);
    BYOVD_UNLOCK();
    DEBUG_CAVE("  DOS e_lfanew read: ok=%d val=0x%X (VA=0x%I64X)",
               rdDos, (UINT32)e_lfanew, moduleBase + 0x3C);
    if (!rdDos) { DEBUG_CAVE("  FAIL: could not read DOS e_lfanew"); return FALSE; }
    if (e_lfanew < 0 || e_lfanew > 0x1000) {
        DEBUG_CAVE("  FAIL: e_lfanew out of range (0x%X)", (UINT32)e_lfanew);
        return FALSE;
    }

    UINT64 ntH = moduleBase + (UINT32)e_lfanew;
    DEBUG_CAVE("  NT headers VA=0x%I64X", ntH);

    /* PE signature */
    UINT32 sig = 0;
    BYOVD_LOCK();
    BOOL rdSig = BYOVD_ReadVA(cr3, ntH, &sig, 4);
    BYOVD_UNLOCK();
    DEBUG_CAVE("  PE signature read: ok=%d val=0x%08X (expect 0x00004550)", rdSig, sig);
    if (!rdSig || sig != 0x00004550) {
        DEBUG_CAVE("  FAIL: PE signature mismatch or unreadable");
        return FALSE;
    }

    /* COFF: NumberOfSections at ntH+6 */
    USHORT numSections = 0;
    BYOVD_LOCK(); BYOVD_ReadVA(cr3, ntH + 6, &numSections, 2); BYOVD_UNLOCK();
    DEBUG_CAVE("  NumberOfSections=%u", numSections);

    /* SizeOfOptionalHeader at ntH+20 */
    USHORT optSize = 0;
    BYOVD_LOCK(); BYOVD_ReadVA(cr3, ntH + 20, &optSize, 2); BYOVD_UNLOCK();
    DEBUG_CAVE("  SizeOfOptionalHeader=0x%X", optSize);

    UINT64 secBase = ntH + 24 + optSize;
    DEBUG_CAVE("  First section header VA=0x%I64X", secBase);

    for (USHORT i = 0; i < numSections && i < 96; i++) {
        UINT64 sec = secBase + (UINT64)i * 40;
        char name[9] = {0};
        BYOVD_LOCK();
        if (!BYOVD_ReadVA(cr3, sec, name, 8)) {
            BYOVD_UNLOCK();
            DEBUG_CAVE("  Section[%u]: read fail at 0x%I64X", i, sec);
            continue;
        }
        BYOVD_UNLOCK();
        DEBUG_CAVE("  Section[%u]: name=\"%s\" VA=0x%I64X", i, name, sec);
        if (memcmp(name, ".text", 5) == 0) {
            UINT32 vsize = 0, rva = 0;
            BYOVD_LOCK();
            BOOL rv  = BYOVD_ReadVA(cr3, sec + 8,  &vsize, 4);
            BOOL rv2 = BYOVD_ReadVA(cr3, sec + 12, &rva,   4);
            BYOVD_UNLOCK();
            DEBUG_CAVE("  .text found: VirtualSize=0x%X RVA=0x%X (reads ok=%d,%d)",
                       vsize, rva, rv, rv2);
            if (rva && vsize) {
                *outRVA  = rva;
                *outSize = vsize;
                DEBUG_CAVE("  GetTextSection OK: rva=0x%X size=0x%X", rva, vsize);
                return TRUE;
            }
            DEBUG_CAVE("  FAIL: .text has zero RVA or VirtualSize");
        }
    }
    DEBUG_CAVE("  FAIL: .text section not found in %u sections", numSections);

    /* FALLBACK: if PE/DOS headers are wiped or corrupt, apply a robust dynamic fallback.
     * We attempt to query SizeOfImage from Optional Header, falling back to 100MB if needed. */
    LONG e_lfanew_fb = 0;
    BYOVD_LOCK();
    BOOL rdDos_fb = BYOVD_ReadVA(cr3, moduleBase + 0x3C, &e_lfanew_fb, 4);
    BYOVD_UNLOCK();

    UINT32 sizeOfImage = 0x6400000; // 100MB fallback default
    if (rdDos_fb && e_lfanew_fb > 0 && e_lfanew_fb < 0x1000) {
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, moduleBase + e_lfanew_fb + 0x50, &sizeOfImage, 4);
        BYOVD_UNLOCK();
    }
    if (sizeOfImage < 0x10000) {
        sizeOfImage = 0x6400000;
    }
    *outRVA = 0x1000;
    *outSize = sizeOfImage - 0x1000;
    return TRUE;
}

/* ── Insertion sort: caves by size descending ───────────────────────────── */
static void SortCaves(CaveInfo *arr, int n) {
    for (int i = 1; i < n; i++) {
        CaveInfo tmp = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j].size < tmp.size) { arr[j+1] = arr[j]; j--; }
        arr[j+1] = tmp;
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

__declspec(noinline)
#pragma optimize("", off)
int CaveFinder_Scan(UINT64 cr3, UINT64 moduleBase,
                    UINT32 minSize, CaveInfo *out, int maxOut)
{
    /* MUTATE: code-cave scanner is the foundation of every hook install.
     * Mutating obscures the 0xCC/0x00 run-length scan loop.
     * noinline: CaveFinder_FindNearNoReserve calls this and also has MUTATE_ST_ART
     * — without noinline LTCG would create nested markers. */
    MUTATE_START
    int    found    = 0;
    UINT32 runsHit  = 0;
    UINT32 pagesFail= 0;
    DEBUG_CAVE("=== CaveFinder_Scan START ===");
    DEBUG_CAVE("  cr3=0x%I64X moduleBase=0x%I64X minSize=%u maxOut=%d",
               cr3, moduleBase, minSize, maxOut);

    if (!out || maxOut <= 0 || minSize < 5) {
        DEBUG_CAVE("  FAIL: invalid params (out=%p maxOut=%d minSize=%u)",
                   (void*)out, maxOut, minSize);
        goto _cfs_end;
    }

    UINT32 textRVA = 0, textSize = 0;
    if (!GetTextSection(cr3, moduleBase, &textRVA, &textSize)) {
        DEBUG_CAVE("  FAIL: GetTextSection returned FALSE");
        goto _cfs_end;
    }

    UINT64 textVA  = moduleBase + textRVA;
    UINT32 pages   = (textSize + 4095) / 4096;
    DEBUG_CAVE("  .text VA=0x%I64X size=0x%X (%u bytes, %u pages)",
               textVA, textSize, textSize, pages);
    DEBUG_CAVE("  Scanning for CC/00 padding runs >= %u bytes...", minSize);

    UINT8  page[4096];
    UINT32 runStart = 0;
    UINT32 runLen   = 0;
    BOOL   inRun    = FALSE;
    BOOL   isZeroRun= FALSE;

    for (UINT32 off = 0; off < textSize && found < maxOut; off += 4096) {
        UINT32 chunk = textSize - off;
        if (chunk > 4096) chunk = 4096;

        /* Log every 256 pages (~1MB progress) */
        if ((off & 0xFFFFF) == 0) {
            DEBUG_CAVE("  Progress: offset=0x%X / 0x%X (%.1f%%) found=%d",
                       off, textSize, (float)off*100.f/(float)textSize, found);
        }

        BYOVD_LOCK();
        BOOL pageOk = BYOVD_ReadVA(cr3, textVA + off, page, chunk);
        BYOVD_UNLOCK();

        if (!pageOk) {
            DEBUG_CAVE("  Page FAIL: VA=0x%I64X offset=0x%X size=%u",
                       textVA + off, off, chunk);
            pagesFail++;
            if (inRun) {
                if (runLen >= minSize && found < maxOut) {
                    DEBUG_CAVE("  Cave (page-break) #%d: VA=0x%I64X size=%u",
                               found, textVA + runStart, runLen);
                    UINT32 safeStart = runStart;
                    UINT32 safeLen   = runLen;
                    if (isZeroRun) { safeStart += 2; safeLen -= 4; }
                    out[found].va   = textVA + safeStart;
                    out[found].size = safeLen;
                    found++;
                }
                inRun = FALSE; runLen = 0;
            }
            continue;
        }

        for (UINT32 i = 0; i < chunk; i++) {
            UINT8 b = page[i];
            /* Accept 0xCC or 0x00. But for 0x00, enforce stricter size checks. */
            if (b == 0xCC || b == 0x00) {
                if (!inRun) { 
                    runStart = off + i; 
                    runLen = 1; 
                    inRun = TRUE; 
                    isZeroRun = (b == 0x00);
                } else {
                    runLen++;
                    if (b == 0xCC) isZeroRun = FALSE; /* If there's any CC, treat as reliable CC cave */
                }
            } else {
                if (inRun) {
                    runsHit++;
                    /* If it's a zero run, require at least 64 bytes to guarantee it's real padding, 
                     * not just zeros embedded in instruction operands or small arrays. */
                    /* Using a tight requirement since Destiny 2 has zero-runs, but we add a safety margin
                     * to avoid touching operands at the boundary. */
                    UINT32 required = isZeroRun ? (minSize + 4) : minSize;
                    if (runLen >= required && found < maxOut) {
                        UINT32 safeStart = runStart;
                        UINT32 safeLen   = runLen;
                        if (isZeroRun) { safeStart += 2; safeLen -= 4; }
                        
                        DEBUG_CAVE("  Cave #%d: VA=0x%I64X size=%u (offset=0x%X) isZero=%d",
                                   found, textVA + safeStart, safeLen, safeStart, isZeroRun);
                        out[found].va   = textVA + safeStart;
                        out[found].size = safeLen;
                        found++;
                    } else if (runLen >= minSize) {
                        DEBUG_CAVE("  Cave (rejected/overflow): VA=0x%I64X size=%u isZero=%d",
                                   textVA + runStart, runLen, isZeroRun);
                    }
                    inRun = FALSE; runLen = 0;
                }
            }
        }
    }

    /* Flush trailing run */
    if (inRun) {
        runsHit++;
        UINT32 required = isZeroRun ? (minSize + 4) : minSize;
        if (runLen >= required && found < maxOut) {
            UINT32 safeStart = runStart;
            UINT32 safeLen   = runLen;
            if (isZeroRun) { safeStart += 2; safeLen -= 4; }
            out[found].va   = textVA + safeStart;
            out[found].size = safeLen;
            found++;
        }
    }

    DEBUG_CAVE("  Scan complete: totalPadRuns=%u pagesFailed=%u", runsHit, pagesFail);

    SortCaves(out, found);

    DEBUG_CAVE("=== CaveFinder_Scan RESULTS (%d caves >= %u bytes) ===", found, minSize);
    for (int i = 0; i < found; i++) {
        DEBUG_CAVE("  [%d] VA=0x%I64X size=%u end=0x%I64X",
                   i, out[i].va, out[i].size, out[i].va + out[i].size);
    }
    if (found == 0) DEBUG_CAVE("  No caves found. Check .text section or minSize.");
    DEBUG_CAVE("=== CaveFinder_Scan END ===");
_cfs_end:
    MUTATE_END
    return found;
}
#pragma optimize("", on)

/* ── Reservation table ────────────────────────────────────────────────────
 * Multiple modules (silent_aim, chams, rapid_fire, revive, cam-hook, LP-hook)
 * call CaveFinder_FindFirst / FindNear independently.  Without bookkeeping
 * they all converge on the same largest cave and overwrite each other's
 * shellcode, causing mid-execution crashes.  The reservation table records
 * every cave returned by FindFirst and FindNear so subsequent calls skip
 * overlapping ranges.  CaveFinder_ClearReservations() must be called at the
 * start of each FeatureInitThread before any OnAttach hook installs. */
#define CAVE_RES_MAX 32
typedef struct { UINT64 va; UINT32 size; } CaveReservation;
static CaveReservation s_resv[CAVE_RES_MAX];
static int             s_resvCount = 0;

static BOOL CaveOverlapsReserved(UINT64 va, UINT32 size)
{
    UINT64 endA = va + size;
    for (int i = 0; i < s_resvCount; i++) {
        UINT64 endB = s_resv[i].va + s_resv[i].size;
        if (va < endB && s_resv[i].va < endA) return TRUE;
    }
    return FALSE;
}

BOOL CaveFinder_Reserve(UINT64 va, UINT32 size)
{
    if (s_resvCount >= CAVE_RES_MAX) {
        DEBUG_CAVE("CaveFinder_Reserve: table full, refusing 0x%I64X+%u", va, size);
        return FALSE;
    }
    s_resv[s_resvCount].va   = va;
    s_resv[s_resvCount].size = size;
    s_resvCount++;
    DEBUG_CAVE("CaveFinder_Reserve: 0x%I64X size=%u (total=%d)", va, size, s_resvCount);
    return TRUE;
}

UINT32 CaveFinder_GetReservedSize(UINT64 va)
{
    for (int i = 0; i < s_resvCount; i++) {
        if (s_resv[i].va == va) return s_resv[i].size;
    }
    return 0;
}


void CaveFinder_ClearReservations(void)
{
    s_resvCount = 0;
    DEBUG_CAVE("CaveFinder_ClearReservations");
}

UINT64 CaveFinder_FindFirst(UINT64 cr3, UINT64 moduleBase, UINT32 requiredSize)
{
    DEBUG_CAVE("CaveFinder_FindFirst: requiredSize=%u", requiredSize);
    /* Scan multiple candidates so we can skip already-reserved caves.
     * Without this, two back-to-back FindFirst calls (e.g. cam hook and
     * LP hook in Fly_OnAttach) both receive the same largest cave, causing
     * their shellcodes to overlap — when the cam hook fires it executes LP
     * shellcode with wrong registers → movups xmm6,[rcx+0x1C0] with garbage
     * rcx → AV → D2 crash. */
    CaveInfo caves[32];
    int n = CaveFinder_Scan(cr3, moduleBase, requiredSize, caves, 32);
    for (int i = 0; i < n; i++) {
        if (!CaveOverlapsReserved(caves[i].va, caves[i].size)) {
            /* Probe the first byte of the cave to verify residency/writability in physical RAM */
            UINT8 tb = 0;
            BYOVD_LOCK();
            BOOL rOk = BYOVD_ReadVA(cr3, caves[i].va, &tb, 1);
            BYOVD_UNLOCK();
            if (!rOk) {
                DEBUG_CAVE("CaveFinder_FindFirst: read probe FAIL for 0x%I64X", caves[i].va);
                continue;
            }

            BYOVD_LOCK();
            BOOL wOk = BYOVD_WriteVA_Fresh(cr3, caves[i].va, &tb, 1);
            BYOVD_UNLOCK();
            if (!wOk) {
                DEBUG_CAVE("CaveFinder_FindFirst: write probe FAIL for 0x%I64X", caves[i].va);
                continue;
            }

            /* Reserve only the bytes this caller actually needs — NOT the full
             * cave size.  If the full cave (e.g. 4 KB) were reserved, every
             * subsequent CaveFinder_FindNear call would compute:
             *   skip = (resv.va + 4096) - cVA == 4096 >= cLeft == 4096
             * which sets cLeft=0 and marks the entire cave as consumed.  On
             * PCs with only one writable cave in .text, this leaves nothing
             * for Aura, ImmuneBoss, RapidFire, etc., causing "cave not found"
             * for every hook-based feature after Fly_OnAttach.
             * Reserving only requiredSize leaves the tail available so the
             * FindNear advancement logic (cave_finder.c:431-446) can slice
             * the remainder into independent feature-sized chunks.           */
            CaveFinder_Reserve(caves[i].va, requiredSize);

            DEBUG_CAVE("CaveFinder_FindFirst: result=0x%I64X size=%u (OK, reserved)", caves[i].va, caves[i].size);
            return caves[i].va;
        }
        DEBUG_CAVE("CaveFinder_FindFirst: cave[%d]=0x%I64X skipped (reserved)", i, caves[i].va);
    }
    DEBUG_CAVE("CaveFinder_FindFirst: result=0 (NOT FOUND or all reserved)");
    return 0;
}

/* ── Internal worker (no reservation) ────────────────────────────────────── */
#pragma optimize("", off)
UINT64 CaveFinder_FindNearNoReserve(UINT64 cr3, UINT64 moduleBase,
                                    UINT32 requiredSize, UINT64 nearVA)
{
    /* MUTATE: cave selection near a hook target — mutating obscures the
     * ±2MB radius scan and the writable-page validation logic. */
    MUTATE_START
    UINT64 _cfn_result = 0;
    DEBUG_CAVE("CaveFinder_FindNearNoReserve: requiredSize=%u nearVA=0x%I64X", requiredSize, nearVA);

    /* Get .text bounds */
    UINT32 textRva = 0, textSize = 0;
    if (!GetTextSection(cr3, moduleBase, &textRva, &textSize)) {
        DEBUG_CAVE("CaveFinder_FindNear: GetTextSection failed");
        goto _cfn_end;
    }
    UINT64 textVA  = moduleBase + textRva;
    UINT64 textEnd = textVA + textSize;

    /* Scan ±2MB around nearVA, clamped to .text bounds */
#define NEAR_RADIUS 0x200000ULL
    UINT64 scanStart = (nearVA > textVA  + NEAR_RADIUS) ? (nearVA - NEAR_RADIUS) : textVA;
    UINT64 scanEnd   = (nearVA + NEAR_RADIUS < textEnd) ? (nearVA + NEAR_RADIUS) : textEnd;
    /* Page-align start */
    scanStart = scanStart & ~0xFFFULL;

    DEBUG_CAVE("CaveFinder_FindNear: scanning 0x%I64X - 0x%I64X", scanStart, scanEnd);

    UINT64 runStart = 0;
    UINT32 runLen   = 0;
    UINT8  runByte  = 0;

    for (UINT64 va = scanStart; va < scanEnd; va += 0x1000) {
        UINT8 page[0x1000];
        memset(page, 0, sizeof(page));
        BYOVD_LOCK();
        BOOL ok = BYOVD_ReadVA(cr3, va, page, 0x1000);
        BYOVD_UNLOCK();
        if (!ok) { runLen = 0; continue; }

        ULONG limit = (va + 0x1000 > scanEnd) ? (ULONG)(scanEnd - va) : 0x1000;
        for (ULONG i = 0; i < limit; i++) {
            UINT8 b = page[i];
            if (b == 0xCC || b == 0x00) {
                if (runLen == 0) { runStart = va + i; runByte = b; }
                if (b == runByte) {
                    runLen++;
                    if (runLen >= requiredSize) {
                        INT64 delta = (INT64)runStart - (INT64)(nearVA + 5);
                        if (delta >= -0x7FFFFFFFLL && delta <= 0x7FFFFFFFLL) {
                            if (CaveOverlapsReserved(runStart, requiredSize)) {
                                /* Skip this cave — but keep scanning the run, the
                                 * reserved region might end before the run does. */
                                runLen = 0;
                                continue;
                            }
                            /* Write-test before accepting — confirm physical page is writable.
                               Must use _Fresh (forces new PTE walk) — a stale cached PA could
                               write to the wrong physical page and silently corrupt it. */
                            UINT8 tb = runByte; /* same value as all bytes in this run */
                            BYOVD_LOCK(); BOOL wOk = BYOVD_WriteVA_Fresh(cr3, runStart, &tb, 1); BYOVD_UNLOCK();
                            if (!wOk) {
                                DEBUG_CAVE("CaveFinder_FindNear: write test FAIL near cave=0x%I64X — skipping", runStart);
                                runLen = 0;
                                continue;
                            }
                            DEBUG_CAVE("CaveFinder_FindNear: found writable cave=0x%I64X size=%u delta=%I64d",
                                       runStart, runLen, delta);
                            _cfn_result = runStart;
                            goto _cfn_end;
                        }
                    }
                } else {
                    runStart = va + i; runByte = b; runLen = 1;
                }
            } else {
                runLen = 0;
            }
        }
    }

    DEBUG_CAVE("CaveFinder_FindNear: NOT FOUND in ±2MB — trying full .text scan");

    /* Fallback: scan entire .text; two passes:
     *   pass 0: prefer 0xCC caves (file-backed, always writable)
     *   pass 1: allow 0x00 caves (demand-zero, may fail — write-tested below)
     * Each candidate gets a 1-byte write test before being accepted. */
    CaveInfo fallback[CAVE_MAX_RESULTS];
    int nf = CaveFinder_Scan(cr3, moduleBase, requiredSize, fallback, CAVE_MAX_RESULTS);
    for (int pass = 0; pass < 2; pass++) {
        UINT64 bestVA   = 0;
        UINT64 bestDist = (UINT64)-1;
        /* First collect the nearest candidate for this pass.
         * If a cave's START overlaps a reservation, advance cVA past it
         * and use the remaining tail of the run — rather than discarding
         * the entire CC run just because the reservation sits at its head. */
        for (int i = 0; i < nf; i++) {
            UINT64 cVA   = fallback[i].va;
            UINT32 cLeft = fallback[i].size;

            /* Advance cVA past any reservations that contain it (repeat
             * until stable, handles back-to-back reservations). */
            BOOL advanced = TRUE;
            while (advanced && cLeft >= requiredSize) {
                advanced = FALSE;
                for (int r = 0; r < s_resvCount; r++) {
                    UINT64 rEnd = s_resv[r].va + s_resv[r].size;
                    if (cVA >= s_resv[r].va && cVA < rEnd) {
                        UINT64 skip = rEnd - cVA;
                        if (skip >= (UINT64)cLeft) { cLeft = 0; break; }
                        cVA  += skip;
                        cLeft -= (UINT32)skip;
                        advanced = TRUE;
                    }
                }
            }
            if (cLeft < requiredSize) continue;
            if (CaveOverlapsReserved(cVA, requiredSize)) continue;

            INT64 delta = (INT64)cVA - (INT64)(nearVA + 5);
            if (delta < -0x7FFFFFFFLL || delta > 0x7FFFFFFFLL) continue;
            UINT8 b = 0;
            BYOVD_LOCK(); BYOVD_ReadVA(cr3, cVA, &b, 1); BYOVD_UNLOCK();
            if (pass == 0 && b != 0xCC) continue; /* skip 0x00 on first pass */
            UINT64 dist = (delta < 0) ? (UINT64)(-delta) : (UINT64)delta;
            if (dist < bestDist) { bestDist = dist; bestVA = cVA; }
        }
        if (!bestVA) continue;
        /* Write-test: write the same byte back (no-op) to confirm physical writability.
         * If the read fails we MUST NOT proceed — writing tb=0 (uninitialised default)
         * would corrupt a 0xCC cave to 0x00. */
        UINT8 tb = 0;
        BYOVD_LOCK(); BOOL rOk = BYOVD_ReadVA(cr3, bestVA, &tb, 1); BYOVD_UNLOCK();
        if (!rOk) {
            DEBUG_CAVE("CaveFinder_FindNear: read-back FAIL pass=%d cave=0x%I64X — skip", pass, bestVA);
            continue;
        }
        /* Same rationale: _Fresh to avoid stale-PA corruption on probe write */
        BYOVD_LOCK(); BOOL wOk = BYOVD_WriteVA_Fresh(cr3, bestVA, &tb, 1); BYOVD_UNLOCK();
        if (!wOk) {
            DEBUG_CAVE("CaveFinder_FindNear: write test FAIL pass=%d cave=0x%I64X", pass, bestVA);
            continue;
        }
        DEBUG_CAVE("CaveFinder_FindNear: fallback writable cave=0x%I64X dist=%I64u pass=%d", bestVA, bestDist, pass);
        _cfn_result = bestVA;
        goto _cfn_end;
    }
    DEBUG_CAVE("CaveFinder_FindNear: fallback — no writable cave found");
_cfn_end:
    MUTATE_END
    return _cfn_result;
}
#pragma optimize("", on)

/* ── Public wrapper: auto-reserve on success ─────────────────────────────── */
UINT64 CaveFinder_FindNear(UINT64 cr3, UINT64 moduleBase,
                           UINT32 requiredSize, UINT64 nearVA)
{
    UINT64 va = CaveFinder_FindNearNoReserve(cr3, moduleBase, requiredSize, nearVA);
    if (va) CaveFinder_Reserve(va, requiredSize);
    return va;
}

