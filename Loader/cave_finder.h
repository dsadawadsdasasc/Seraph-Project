#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Describes a contiguous run of CC (INT3) or 00 (null pad) bytes in the .text section */
typedef struct {
    UINT64 va;      /* virtual address of the first padding byte */
    UINT32 size;    /* number of contiguous padding bytes         */
} CaveInfo;

#define CAVE_MAX_RESULTS 32

/* Scan the .text section of the PE at moduleBase for CC or 00 padding caves
 * of at least minSize bytes.  Results are sorted largest-first.
 * Returns the number of caves found (up to maxOut). */
int CaveFinder_Scan(UINT64 cr3, UINT64 moduleBase,
                    UINT32 minSize,
                    CaveInfo *out, int maxOut);

/* Find the first cave that is >= requiredSize bytes.
 * Convenience wrapper around CaveFinder_Scan.
 * Returns the cave VA, or 0 if none found. */
UINT64 CaveFinder_FindFirst(UINT64 cr3, UINT64 moduleBase, UINT32 requiredSize);

/* Find a cave >= requiredSize bytes that is within +-2GB of nearVA (for E9 rel32 reach).
 * Returns the cave VA, or 0 if none found.
 *
 * The returned cave is automatically RESERVED (added to an internal exclusion
 * list) so subsequent calls won't return an overlapping address.  Callers
 * that don't want auto-reservation should use CaveFinder_FindNearNoReserve. */
UINT64 CaveFinder_FindNear(UINT64 cr3, UINT64 moduleBase, UINT32 requiredSize, UINT64 nearVA);

/* Same as CaveFinder_FindNear but does NOT reserve the returned cave. */
UINT64 CaveFinder_FindNearNoReserve(UINT64 cr3, UINT64 moduleBase,
                                    UINT32 requiredSize, UINT64 nearVA);

/* Reserve a region [va, va+size) so future CaveFinder_FindNear calls skip it.
 * Returns FALSE if the reservation table is full (silent overflow protection). */
BOOL CaveFinder_Reserve(UINT64 va, UINT32 size);

/* Get the size of a reserved cave by its virtual address. Returns 0 if not found. */
UINT32 CaveFinder_GetReservedSize(UINT64 va);

/* Drop all reservations (call from OnDetach if you want a clean slate). */
void CaveFinder_ClearReservations(void);

#ifdef __cplusplus
}
#endif
