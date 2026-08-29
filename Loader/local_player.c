
#include "ThemidaSDK.h"
#include "local_player.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "esp.h"
#include "tigerlist.h"
#include "fly.h"
#include "lists.h"
#include "aob_patterns.h"
#include "sobject_list.h"
#include "syscalls.h"  /* SeraphSleep */
#include <math.h>

UINT64 g_local_identity_rva = 0;
UINT64 g_character_motion_vtable_rva = 0;

/* Disable compiler optimization for the entire translation unit.
 * Release build (/O2) optimizations aggressively reorder and cache
 * local player pointer decryption caching and thread index lookup. */
#pragma optimize("", off)


/* ── Static state ──────────────────────────────────────────────────────── */
static UINT64 s_entityVA        = 0;
static int    s_lpCachedIndex   = -1;
static DWORD  s_lpLastReadMs    = 0;
static UINT64 s_lpRigidBodyVA   = 0;
static UINT32 s_lpSObjectHandle = 0;
static UINT64 s_lpMgrInstanceVA = 0;
static float  s_lpSObjectPos[3] = {0};
static BOOL   s_lpSObjectPosValid = FALSE;

static volatile LONG s_lp_lock_val = 0;
static void _lp_lock(void)   { while (InterlockedCompareExchange(&s_lp_lock_val, 1, 0) == 1) { SeraphSleep(0); } }
static void _lp_unlock(void) { InterlockedExchange(&s_lp_lock_val, 0); }

/* ═══════════════════════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

void LP_OnAttach(void)
{
    MUTATE_START
    _lp_lock();
    s_entityVA        = 0;
    s_lpCachedIndex   = -1;
    s_lpLastReadMs    = 0;
    s_lpRigidBodyVA   = 0;
    s_lpSObjectHandle = 0;
    s_lpMgrInstanceVA = 0;
    s_lpSObjectPos[0] = s_lpSObjectPos[1] = s_lpSObjectPos[2] = 0.0f;
    s_lpSObjectPosValid = FALSE;
    _lp_unlock();
    MUTATE_END
}


void LP_OnDetach(void)
{
    _lp_lock();
    s_entityVA        = 0;
    s_lpCachedIndex   = -1;
    s_lpLastReadMs    = 0;
    s_lpRigidBodyVA   = 0;
    s_lpSObjectHandle = 0;
    s_lpMgrInstanceVA = 0;
    _lp_unlock();
}

static UINT64 ResolveRipTarget(UINT64 cr3, UINT64 match_va, int disp_offset, int instr_len) {
    INT32 disp = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, match_va + disp_offset, &disp, 4);
    BYOVD_UNLOCK();
    if (!ok) return 0;
    return match_va + instr_len + (INT64)disp;
}

void LP_ResolveGlobalsIfNeeded(UINT64 cr3, UINT64 d2Base) {
    if (!cr3 || !d2Base) return;
    
    if (g_local_identity_rva == 0) {
        g_local_identity_rva = SecureReadStatic(&OBF_OFF_LocalIdentity);
        DEBUG_FLY("LP_ResolveGlobals: Resolved LOCAL_IDENTITY RVA = 0x%I64X (Secure)", g_local_identity_rva);
    }
    
    if (g_character_motion_vtable_rva == 0) {
        g_character_motion_vtable_rva = SecureReadStatic(&OBF_OFF_CharMotionVtable);
        DEBUG_FLY("LP_ResolveGlobals: Resolved CHARACTER_MOTION_VTABLE RVA = 0x%I64X (Secure)", g_character_motion_vtable_rva);
    }

    if (s_lpMgrInstanceVA == 0) {
        BYOVD_LOCK();
        UINT64 match_va = BYOVD_ScanPatternText(cr3, d2Base, k_lpmgr_pat, k_lpmgr_mask, 22);
        BYOVD_UNLOCK();
        if (match_va >= d2Base) {
            UINT64 target_va = ResolveRipTarget(cr3, match_va, 3, 7);
            if (target_va >= d2Base) {
                s_lpMgrInstanceVA = target_va;
                DEBUG_FLY("LP_ResolveGlobals: Resolved LocalPlayerManager VA = 0x%I64X (via AOB @ 0x%I64X)", s_lpMgrInstanceVA, match_va);
            }
        }
    }
}

static void _log_hex_dump(UINT64 cr3, UINT64 va, int size, const char *tag) {
    BYTE buf[128];
    if (size > 128) size = 128;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, va, buf, size);
    BYOVD_UNLOCK();
    if (!ok) {
        DEBUG_FLY("[DUMP][%s] Failed to read VA 0x%I64X (sz=%d)", tag, va, size);
        return;
    }
    char hexStr[300] = {0};
    int pos = 0;
    for (int i = 0; i < size && pos < 280; i++) {
        pos += wsprintfA(hexStr + pos, "%02X ", buf[i]);
    }
    DEBUG_FLY("[DUMP][%s] VA=0x%I64X: %s", tag, va, hexStr);
}

void LP_Tick(void)
{
    _lp_lock();
    DWORD now = GetTickCount();
    DWORD interval = 100;
    if (s_lpRigidBodyVA == 0) {
        interval = (Fly_IsEnabled() || FlyDir_IsEnabled()) ? 25 : 50;
    }
    if (now - s_lpLastReadMs < interval) {
        _lp_unlock();
        return;
    }
    s_lpLastReadMs = now;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) {
        _lp_unlock();
        return;
    }

    LP_ResolveGlobalsIfNeeded(cr3, d2Base);

    /* ═══════════════════════════════════════════════════════════════════════
     *  DIRECT SOBJECT COMPONENT CHAIN WALK FOR LOCAL PLAYER
     * ═══════════════════════════════════════════════════════════════════════ */
    if (s_lpMgrInstanceVA >= 0x10000ULL) {
        UINT32 sobjHandle = 0;
        BYOVD_LOCK();
        BOOL rHdl = BYOVD_ReadVA_NoCache(cr3, s_lpMgrInstanceVA + 0x4F0, &sobjHandle, 4);
        BYOVD_UNLOCK();

        if (rHdl && sobjHandle != 0 && sobjHandle != 0xFFFFFFFFu) {
            s_lpSObjectHandle = sobjHandle;
            static UINT32 s_lastLoggedHdl = 0;
            if (sobjHandle != s_lastLoggedHdl) {
                DEBUG_FLY("[LP_WALK] Step 1: Valid SObject Handle = 0x%08X (Manager=0x%I64X+0x4F0)", sobjHandle, s_lpMgrInstanceVA);
                s_lastLoggedHdl = sobjHandle;
            }

            /* Step 2: Resolve SObject Entry in SObject table
             * SObjectListBase (D2Base + 0x27F5778) is a descriptor containing:
             *   +0x00: uint64_t sobjArrayBase (e.g. 0x6F2D5A80)
             *   +0x08: uint32_t sobjStride    (0xE0 = 224 bytes)
             */
            UINT64 descriptorVA = d2Base + SecureReadStatic(&OBF_OFF_SObjectListBase);
            UINT64 sobjArrayBase = 0;
            UINT32 sobjStride = 0xE0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, descriptorVA, &sobjArrayBase, 8);
            BYOVD_ReadVA_NoCache(cr3, descriptorVA + 0x08, &sobjStride, 4);
            BYOVD_UNLOCK();

            if (sobjStride == 0 || sobjStride > 0x1000) sobjStride = 0xE0;
            if (sobjArrayBase < 0x10000ULL) sobjArrayBase = descriptorVA; // fallback

            UINT64 sobjEntryVA = sobjArrayBase + (UINT64)(sobjHandle & 0x1FFFu) * (UINT64)sobjStride;
            
            static UINT32 s_lastWalkedHdl = 0;
            BOOL shouldLogWalk = (sobjHandle != s_lastWalkedHdl);
            if (shouldLogWalk) {
                DEBUG_FLY("[LP_WALK] SObject Handle = 0x%08X -> Entry VA=0x%I64X", sobjHandle, sobjEntryVA);
                s_lastWalkedHdl = sobjHandle;
            }

            /* Step 2.1: Read Position from SObject Entry (+0xC0 and +0xD0) */
            float encPos[3] = {0};
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, sobjEntryVA + 0xC0, encPos, 12);
            BYOVD_UNLOCK();

            if (!g_EspState.keys_valid) {
                ESP_Init();
            }

            float decPos[3] = {0};
            if (g_EspState.keys_valid && g_EspState.key4 != 0) {
                if (SObjectList_DecryptPosition(encPos, g_EspState.key4, decPos)) {
                    if ((decPos[0] != 0.0f || decPos[1] != 0.0f || decPos[2] != 0.0f) &&
                        fabsf(decPos[0]) < 500000.0f && fabsf(decPos[1]) < 500000.0f && fabsf(decPos[2]) < 500000.0f) {
                        s_lpSObjectPos[0] = decPos[0];
                        s_lpSObjectPos[1] = decPos[1];
                        s_lpSObjectPos[2] = decPos[2];
                        s_lpSObjectPosValid = TRUE;
                        if (shouldLogWalk) {
                            DEBUG_FLY("[LP_WALK] SObject +0xC0 Decrypted Pos = (%.2f, %.2f, %.2f) (raw=[0x%08X 0x%08X 0x%08X])",
                                      decPos[0], decPos[1], decPos[2],
                                      *(UINT32*)&encPos[0], *(UINT32*)&encPos[1], *(UINT32*)&encPos[2]);
                        }
                    }
                }
            } else {
                if (shouldLogWalk) {
                    DEBUG_FLY("[LP_WALK] SObject Pos: key4 not ready (keys_valid=%d, key4=0x%08X)",
                              g_EspState.keys_valid, g_EspState.key4);
                }
            }

            /* Step 3: Read Component Ticket / Handle from SObject + 0x4C */
            UINT32 compTicket = 0;
            BYOVD_LOCK();
            BOOL rCompHdl = BYOVD_ReadVA_NoCache(cr3, sobjEntryVA + 0x4C, &compTicket, 4);
            BYOVD_UNLOCK();

            if (rCompHdl && compTicket != 0 && compTicket != 0xFFFFFFFFu) {
                if (shouldLogWalk) {
                    DEBUG_FLY("[LP_WALK] Head Component Ticket @ +0x4C = 0x%08X (datum_valid=%d)", 
                              compTicket, g_EspState.datum_valid);
                }

                /* Step 4: Traverse the Component Linked List */
                UINT32 curTicket = compTicket;
                UINT64 candRB = 0;

                for (int hop = 0; hop < 32 && curTicket != 0 && curTicket != 0xFFFFFFFFu; hop++) {
                    UINT64 compVA = esp_datum_resolve(cr3, curTicket);
                    if (compVA < 0x10000ULL) {
                        if (shouldLogWalk) {
                            DEBUG_FLY("[LP_WALK] Hop %d: Failed to resolve Ticket=0x%08X (compVA=0x%I64X)", hop, curTicket, compVA);
                        }
                        break;
                    }

                    /* Check component schema / type hash at +0x04 */
                    UINT32 compTypeHash = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA_NoCache(cr3, compVA + 4, &compTypeHash, 4);
                    BYOVD_UNLOCK();

                    if (shouldLogWalk) {
                        DEBUG_FLY("[LP_WALK] Hop %d: Ticket=0x%08X -> CompVA=0x%I64X (Hash=0x%08X)", hop, curTicket, compVA, compTypeHash);
                    }

                    /* Hop 3 (compTypeHash == 0x80A6806C) is Character Physics / Motion Component */
                    if (compTypeHash == 0x80A6806C) {
                        /* In Hop 3, check all 64-bit pointers and sub-tickets */
                        for (UINT32 poff = 0; poff <= 0x50; poff += 8) {
                            UINT64 candPtr = 0;
                            BYOVD_LOCK();
                            BYOVD_ReadVA_NoCache(cr3, compVA + poff, &candPtr, 8);
                            BYOVD_UNLOCK();

                            /* 1. If it's a valid 64-bit heap pointer */
                            if (candPtr >= 0x1000000ULL && candPtr < 0x800000000000ULL && (candPtr & 7) == 0 && candPtr != compVA) {
                                float tCoords[3] = {0};
                                BYOVD_LOCK();
                                BYOVD_ReadVA_NoCache(cr3, candPtr + 0x1C0, tCoords, 12);
                                if (tCoords[0] == 0.0f && tCoords[1] == 0.0f && tCoords[2] == 0.0f) {
                                    BYOVD_ReadVA_NoCache(cr3, candPtr, tCoords, 12);
                                }
                                BYOVD_UNLOCK();

                                if ((tCoords[0] != 0.0f || tCoords[1] != 0.0f || tCoords[2] != 0.0f) &&
                                    fabsf(tCoords[0]) < 50000.0f && fabsf(tCoords[1]) < 50000.0f) {
                                    candRB = candPtr;
                                    if (shouldLogWalk) {
                                        DEBUG_FLY("[LP_WALK] Physics comp +0x%X Direct Ptr -> Payload 0x%I64X (pos: %.2f, %.2f, %.2f)",
                                                  poff, candRB, tCoords[0], tCoords[1], tCoords[2]);
                                    }
                                    break;
                                }
                            }
                        }

                        /* Also test 32-bit sub-tickets (resolved via datum table) */
                        if (!candRB) {
                            for (UINT32 toff = 0; toff <= 0x40; toff += 4) {
                                UINT32 candTicket = 0;
                                BYOVD_LOCK();
                                BYOVD_ReadVA_NoCache(cr3, compVA + toff, &candTicket, 4);
                                BYOVD_UNLOCK();

                                if (candTicket > 0x1000u && candTicket != 0xFFFFFFFFu && candTicket != curTicket && (candTicket >> 13) != 0) {
                                    UINT64 resVA = esp_datum_resolve(cr3, candTicket);
                                    if (resVA >= 0x1000000ULL) {
                                        float tCoords[3] = {0};
                                        BYOVD_LOCK();
                                        BYOVD_ReadVA_NoCache(cr3, resVA + 0x1C0, tCoords, 12);
                                        if (tCoords[0] == 0.0f && tCoords[1] == 0.0f && tCoords[2] == 0.0f) {
                                            BYOVD_ReadVA_NoCache(cr3, resVA, tCoords, 12);
                                        }
                                        BYOVD_UNLOCK();

                                        candRB = resVA;
                                        if (shouldLogWalk) {
                                            DEBUG_FLY("[LP_WALK] Physics comp +0x%X Ticket 0x%08X -> Payload 0x%I64X (pos: %.2f, %.2f, %.2f)",
                                                      toff, candTicket, candRB, tCoords[0], tCoords[1], tCoords[2]);
                                        }
                                        break;
                                    }
                                }
                            }
                        }

                        if (candRB >= 0x1000000ULL) break;
                    }

                    /* Read next ticket in chain from the Datum Table Chunk Entry */
                    UINT32 nextTicket = 0;
                    UINT32 curIdx = (((curTicket >> 13) | 0xFFC0000u) >> 18u) & (curTicket >> 13);
                    if (curIdx <= 0x15000u && g_EspState.datum_valid) {
                        UINT64 chunkVA = g_EspState.datum_table_va + (UINT64)curIdx * 64ULL;
                        DatumRowData row = {0};
                        BYOVD_LOCK();
                        BYOVD_ReadVA_NoCache(cr3, chunkVA + 8, &row, sizeof(row));
                        if (row.entry_base && row.stride) {
                            UINT64 slotVA = row.entry_base + (UINT64)row.stride * (UINT64)(curTicket & 0x1FFFu);
                            BYOVD_ReadVA_NoCache(cr3, slotVA + 0x18, &nextTicket, 4);
                            if (!nextTicket || nextTicket == 0xFFFFFFFFu) {
                                BYOVD_ReadVA_NoCache(cr3, slotVA + 0x1C, &nextTicket, 4);
                            }
                        }
                        BYOVD_UNLOCK();
                    }

                    if (!nextTicket || nextTicket == 0xFFFFFFFFu) {
                        BYOVD_LOCK();
                        BYOVD_ReadVA_NoCache(cr3, compVA + 0x28, &nextTicket, 4);
                        if (!nextTicket || nextTicket == 0xFFFFFFFFu) {
                            BYOVD_ReadVA_NoCache(cr3, compVA + 0x18, &nextTicket, 4);
                        }
                        BYOVD_UNLOCK();
                    }

                    if (nextTicket == curTicket || nextTicket == 0 || nextTicket == 0xFFFFFFFFu) {
                        if (shouldLogWalk) {
                            DEBUG_FLY("[LP_WALK] Hop %d: End of chain (nextTicket=0x%08X)", hop, nextTicket);
                        }
                        break;
                    }
                    curTicket = nextTicket;
                }

                if (candRB >= 0x100000ULL) {
                    float coords[3] = {0};
                    BYOVD_LOCK();
                    BYOVD_ReadVA_NoCache(cr3, candRB + 0x1C0, coords, 12);
                    if (coords[0] == 0.0f && coords[1] == 0.0f && coords[2] == 0.0f) {
                        BYOVD_ReadVA_NoCache(cr3, candRB, coords, 12);
                    }
                    BYOVD_UNLOCK();

                    if (coords[0] != 0.0f || coords[1] != 0.0f || coords[2] != 0.0f) {
                        s_lpRigidBodyVA = candRB;
                        static UINT64 s_lastLogRb = 0;
                        if (s_lpRigidBodyVA != s_lastLogRb) {
                            DEBUG_FLY("[LP_WALK] SUCCESS! Local Player RigidBody/Motion = 0x%I64X (pos: %.2f, %.2f, %.2f)",
                                      s_lpRigidBodyVA, coords[0], coords[1], coords[2]);
                            s_lastLogRb = s_lpRigidBodyVA;
                        }
                    }
                }
            } else {
                if (shouldLogWalk) {
                    DEBUG_FLY("[LP_WALK] SObject + 0x4C invalid (0x%08X)", compTicket);
                }
            }
        } else {
            /* Local player is DEAD / DESPAWNED (0xFFFFFFFF or 0) */
            if (s_lpSObjectHandle != 0) {
                DEBUG_FLY("[LP_WALK] Local Player Dead / Despawned (Handle=0x%08X -> 0x%08X)", s_lpSObjectHandle, sobjHandle);
                s_lpSObjectHandle = 0;
                s_lpRigidBodyVA   = 0;
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════════════════
     *  TIGERLIST FAST MATCH (Matches slotVA + 0x084 == s_lpSObjectHandle)
     * ═══════════════════════════════════════════════════════════════════════ */
    if (s_lpSObjectHandle != 0) {
        UINT64 container = TigerList_GetContainer();
        if (container >= 0x10000ULL) {
            UINT64 arrPtr = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, container + 0x08, &arrPtr, 8);
            BYOVD_UNLOCK();
            if (arrPtr >= 0x10000ULL) {
                for (int ti = 0; ti < TL_MAX_SLOTS; ti++) {
                    UINT64 slotVA = arrPtr + (UINT64)ti * TL_STRIDE;
                    UINT32 slot_sobj = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA_NoCache(cr3, slotVA + 0x084, &slot_sobj, 4);
                    BYOVD_UNLOCK();
                    if (slot_sobj == s_lpSObjectHandle) {
                        s_entityVA = slotVA;
                        s_lpCachedIndex = ti;
                        static int s_lastMatchedSlot = -1;
                        if (ti != s_lastMatchedSlot) {
                            DEBUG_FLY("[LP_WALK] TigerList Slot %d MATCHED via SObject Handle 0x%08X (entityVA=0x%I64X)",
                                      ti, s_lpSObjectHandle, slotVA);
                            s_lastMatchedSlot = ti;
                        }
                        break;
                    }
                }
            }
        }
    }

    _lp_unlock();
}

int LP_GetLocalPlayerIndex(void)
{
    LP_Tick();
    _lp_lock();
    int idx = s_lpCachedIndex;
    _lp_unlock();
    return idx;
}

void LP_ResetSoftState(void)
{
    _lp_lock();
    s_entityVA        = 0;
    s_lpCachedIndex   = -1;
    s_lpLastReadMs    = 0;
    s_lpRigidBodyVA   = 0;
    s_lpSObjectHandle = 0;
    s_lpMgrInstanceVA = 0;
    _lp_unlock();
}

UINT64 LP_GetEntityVA(void)
{
    _lp_lock();
    UINT64 va = s_entityVA;
    _lp_unlock();
    return va;
}

UINT64 LP_GetLocalPlayerRigidBody(void)
{
    LP_Tick();
    _lp_lock();
    UINT64 rb = s_lpRigidBodyVA;
    _lp_unlock();
    return rb;
}

UINT32 LP_GetLocalPlayerSObjectHandle(void)
{
    _lp_lock();
    UINT32 h = s_lpSObjectHandle;
    _lp_unlock();
    return h;
}

BOOL LP_GetLocalPlayerSObjectPos(float outPos[3])
{
    LP_Tick();
    _lp_lock();
    BOOL valid = s_lpSObjectPosValid;
    if (valid && outPos) {
        outPos[0] = s_lpSObjectPos[0];
        outPos[1] = s_lpSObjectPos[1];
        outPos[2] = s_lpSObjectPos[2];
    }
    _lp_unlock();
    return valid;
}

UINT64 LP_GetLocalPlayerSObjectVA(void)
{
    LP_Tick();
    _lp_lock();
    UINT32 sobjHandle = s_lpSObjectHandle;
    _lp_unlock();

    if (!sobjHandle) return 0;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return 0;

    UINT64 descriptorVA = d2Base + SecureReadStatic(&OBF_OFF_SObjectListBase);
    UINT64 sobjArrayBase = 0;
    UINT32 sobjStride = 0xE0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, descriptorVA, &sobjArrayBase, 8);
    BYOVD_ReadVA_NoCache(cr3, descriptorVA + 0x08, &sobjStride, 4);
    BYOVD_UNLOCK();

    if (sobjStride == 0 || sobjStride > 0x1000) sobjStride = 0xE0;
    if (sobjArrayBase < 0x10000ULL) sobjArrayBase = descriptorVA;

    return sobjArrayBase + (UINT64)(sobjHandle & 0x1FFFu) * (UINT64)sobjStride;
}

#pragma optimize("", on)



