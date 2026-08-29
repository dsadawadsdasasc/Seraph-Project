#define HAVOK_IMPLEMENTATION
#include "havok.h"
#include "fly.h"
#include "tigerlist.h"
#include "local_player.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include <math.h>

#pragma optimize("", off)

static UINT64 s_hkp_preScanVA = 0;

void Havok_SetHkpPreScanResult(UINT64 va) {
    s_hkp_preScanVA = va;
}

HavokState g_HavokState = {0};
HavokVec3 g_camWorldPos = {0,0,0};
BOOL g_camWorldPosValid = FALSE;

#include "xor_strings.h"

BOOL Havok_Init(void)
{
    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2base = GetDestiny2Base();
    if (!cr3 || !d2base) return FALSE;

    static DWORD s_lastInitAttempt = 0;
    DWORD now = GetTickCount();

    LP_ResolveGlobalsIfNeeded(cr3, d2base);

    UINT64 instr_va = 0;
    if (s_hkp_preScanVA >= d2base) {
        instr_va = s_hkp_preScanVA;
    } else {
        instr_va = d2base + SecureReadStatic(&OBF_OFF_Havok);
    }

    INT32 disp = 0;
    BOOL ok = FALSE;
    if (instr_va >= d2base) {
        BYOVD_LOCK();
        ok = BYOVD_ReadVA(cr3, instr_va + 3, &disp, 4);
        BYOVD_UNLOCK();
    }

    UINT64 ptr_va = 0;
    UINT64 world_va = 0;
    if (ok && disp != 0) {
        ptr_va = instr_va + 7 + (INT64)disp;
        if (ptr_va >= 0x10000ULL) {
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, ptr_va, &world_va, 8);
            BYOVD_UNLOCK();
        }
    }

    /* If static/cached offset failed or returned invalid ptr, run dynamic AOB scan */
    if (!world_va) {
        if (now - s_lastInitAttempt < 2000) {
            return FALSE; /* Cooldown between AOB scans */
        }
        s_lastInitAttempt = now;

        DEBUG_HAVOK("Havok_Init: static hkpWorld failed (instr=0x%I64X) -- scanning AOB [48 8B 0D ? ? ? ? C1 E8]", instr_va);
        BYOVD_LOCK();
        UINT64 scanned_va = BYOVD_ScanPatternText(cr3, d2base, k_hkp_pat, k_hkp_mask, 9);
        BYOVD_UNLOCK();

        if (scanned_va >= d2base) {
            instr_va = scanned_va;
            disp = 0;
            BYOVD_LOCK();
            BOOL okDisp = BYOVD_ReadVA(cr3, instr_va + 3, &disp, 4);
            BYOVD_UNLOCK();
            if (okDisp && disp != 0) {
                ptr_va = instr_va + 7 + (INT64)disp;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, ptr_va, &world_va, 8);
                BYOVD_UNLOCK();
                DEBUG_HAVOK("Havok_Init: scanned instr_va=0x%I64X ptr_va=0x%I64X world_va=0x%I64X",
                            instr_va, ptr_va, world_va);
            }
        }
    }

    if (!world_va) { 
        DEBUG_HAVOK("Havok_Init: leitura hkpWorld falhou"); 
        return FALSE; 
    }

    g_HavokState.hkp_world_ptr_va = ptr_va;
    g_HavokState.hkp_world_va     = world_va;
    DEBUG_HAVOK("Havok_Init: hkpWorld=0x%I64X ptr_va=0x%I64X OK", world_va, ptr_va);

    return TRUE;
}

void Havok_Reset(void)
{
    g_HavokState.local_entity_ptr = 0;
    g_HavokState.local_pos.x = g_HavokState.local_pos.y = g_HavokState.local_pos.z = 0.0f;
}

int Havok_GetEntities(HavokEntity *out_entities, int max_out)
{
    if (!out_entities || max_out <= 0) return 0;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return 0;

    {
        static DWORD s_worldCheckMs = 0;
        DWORD _now = GetTickCount();
        if (g_HavokState.hkp_world_ptr_va && (DWORD)(_now - s_worldCheckMs) >= 500) {
            s_worldCheckMs = _now;
            UINT64 fresh_world = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, g_HavokState.hkp_world_ptr_va, &fresh_world, 8);
            BYOVD_UNLOCK();
            if (fresh_world && fresh_world != g_HavokState.hkp_world_va) {
                DEBUG_HAVOK("Havok_GetEntities: hkpWorld changed 0x%I64X -> 0x%I64X (area transition)",
                          g_HavokState.hkp_world_va, fresh_world);
                g_HavokState.hkp_world_va      = fresh_world;
                g_HavokState.local_entity_ptr  = 0;
                g_HavokState.hkp_motion_vtable = 0;
            }
        }
    }
    const UINT64 world = g_HavokState.hkp_world_va;
    if (!world) return 0;

    int total_results = 0;

    static const UINT32 list_offsets[] = {
        0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0
    };
    const int list_offsets_n = (int)(sizeof(list_offsets) / sizeof(list_offsets[0]));

    UINT64 seen_lists[16] = {0};
    int    seen_n = 0;

    for (int li = 0; li < list_offsets_n && total_results < max_out; li++)
    {
        IslandListHeader hdr = {0};
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, world + list_offsets[li], &hdr, sizeof(hdr));
        BYOVD_UNLOCK();

        BOOL dup = FALSE;
        if (hdr.list) {
            for (int sx = 0; sx < seen_n; sx++) if (seen_lists[sx] == hdr.list) { dup = TRUE; break; }
        }
        if (dup) continue;
        if (hdr.list && seen_n < 16) seen_lists[seen_n++] = hdr.list;

        if (!hdr.list || hdr.count == 0 || hdr.count > HAVOK_MAX_ISLANDS) continue;

        UINT32 island_count = hdr.count;
        if (island_count > HAVOK_MAX_ISLANDS) island_count = HAVOK_MAX_ISLANDS;

        static UINT64 island_ptrs[HAVOK_MAX_ISLANDS];
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, hdr.list, island_ptrs, island_count * sizeof(UINT64));
        BYOVD_UNLOCK();

        UINT32 accumulated = 0;

        for (UINT32 i = 0; i < island_count && total_results < max_out; i++)
        {
            UINT64 island = island_ptrs[i];
            if (!island) continue;

            IslandListHeader ehdr = {0};
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, island + HAVOK_OFF_ENTITY_LIST, &ehdr, sizeof(ehdr));
            BYOVD_UNLOCK();

            if (!ehdr.list || ehdr.count == 0 || ehdr.count > HAVOK_MAX_ISLANDS) continue;

            UINT32 ecnt = ehdr.count;
            if (ecnt > HAVOK_MAX_ENTITIES) ecnt = HAVOK_MAX_ENTITIES;

            static UINT64 entity_ptrs[HAVOK_MAX_ENTITIES];
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, ehdr.list, entity_ptrs, ecnt * sizeof(UINT64));
            BYOVD_UNLOCK();

            for (UINT32 j = 0; j < ecnt && total_results < max_out; j++)
            {
                UINT64 ep = entity_ptrs[j];
                if (!ep) continue;

                HavokVec3 coords   = {0};
                UINT64    p_motion = 0;
                UINT64    vtable   = 0;

                UINT64 p_hkp_world_ep = 0;
                UINT64 p_collidable    = 0;
                BYTE slab[460];
                BYOVD_LOCK();
                BOOL okSlab = BYOVD_ReadVA(cr3, ep, slab, sizeof(slab));
                BYOVD_UNLOCK();
                if (!okSlab) continue;

                vtable         = *(UINT64*)(slab + RB_OFF_VTABLE);
                p_hkp_world_ep = *(UINT64*)(slab + RB_OFF_P_HKP_WORLD);
                p_collidable   = *(UINT64*)(slab + RB_OFF_P_COLLIDABLE);
                p_motion       = *(UINT64*)(slab + RB_OFF_P_MOTION);
                coords         = *(HavokVec3*)(slab + RB_OFF_COORDS);

                if (!p_hkp_world_ep) continue;

                if (p_collidable) {
                    UINT64 shape = 0;
                    BYOVD_LOCK();
                    BYOVD_ReadVA(cr3, p_collidable, &shape, 8);
                    BYOVD_UNLOCK();
                    if (!shape) continue;
                }

                if (coords.x == 0.0f && coords.y == 0.0f && coords.z == 0.0f) continue;
                if (coords.x != coords.x || coords.y != coords.y) continue;
                if (!p_motion) continue;

                UINT64 motion_vtable = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, p_motion, &motion_vtable, 8);
                BYOVD_UNLOCK();

                float d2 = 0.0f;
                if (g_camWorldPosValid) {
                    float dx = coords.x - g_camWorldPos.x;
                    float dy = coords.y - g_camWorldPos.y;
                    float dz = coords.z - g_camWorldPos.z;
                    d2 = dx*dx + dy*dy + dz*dz;
                }
                out_entities[total_results].entity_ptr    = ep;
                out_entities[total_results].vtable        = vtable;
                out_entities[total_results].motion_vtable = motion_vtable;
                out_entities[total_results].coords        = coords;
                out_entities[total_results].is_local      = FALSE;
                out_entities[total_results].list_tag      = (int)list_offsets[li];
                out_entities[total_results].speed2        = 0.0f;
                out_entities[total_results].dist2         = d2;
                total_results++;
            }

            accumulated += ecnt;
            if (accumulated > HAVOK_MAX_ENTITIES) break;
        }
    }

    UINT64 best_ep = LP_GetLocalPlayerRigidBody();
    if (best_ep < 0x100000ULL && g_character_motion_vtable_rva != 0) {
        UINT64 d2Base = GetDestiny2Base();
        UINT64 target_vt = d2Base + g_character_motion_vtable_rva;
        
        float refPos[3] = {0};
        BOOL hasRefPos = LP_GetLocalPlayerSObjectPos(refPos);
        if (!hasRefPos && g_camWorldPosValid) {
            refPos[0] = g_camWorldPos.x;
            refPos[1] = g_camWorldPos.y;
            refPos[2] = g_camWorldPos.z;
            hasRefPos = TRUE;
        }

        float bestDist2 = 4.0f; /* 2.0 meters max threshold (2^2 = 4.0) */
        DWORD now = GetTickCount();

        for (int i = 0; i < total_results; i++) {
            static DWORD s_lastEntDump = 0;
            if (now - s_lastEntDump >= 4000) {
                s_lastEntDump = now;
                for (int k = 0; k < total_results && k < 10; k++) {
                    DEBUG_HAVOK("[HAVOK_ENT %d] ep=0x%I64X vt=0x%I64X mot_vt=0x%I64X (pos: %.2f, %.2f, %.2f)",
                                k, out_entities[k].entity_ptr, out_entities[k].vtable,
                                out_entities[k].motion_vtable,
                                out_entities[k].coords.x, out_entities[k].coords.y, out_entities[k].coords.z);
                }
            }

            UINT64 ent_mot = out_entities[i].motion_vtable;
            BOOL isMotMatch = (ent_mot == target_vt) ||
                              (g_character_motion_vtable_rva != 0 && ((ent_mot - d2Base) == g_character_motion_vtable_rva)) ||
                              (target_vt != 0 && ((ent_mot & 0xFFFFFF) == (target_vt & 0xFFFFFF)));

            if (isMotMatch) {
                if (hasRefPos) {
                    float dx = out_entities[i].coords.x - refPos[0];
                    float dy = out_entities[i].coords.y - refPos[1];
                    float dz = out_entities[i].coords.z - refPos[2];
                    float dist2 = dx*dx + dy*dy + dz*dz;

                    static DWORD s_lastMotLog = 0;
                    if (now - s_lastMotLog >= 2000) {
                        s_lastMotLog = now;
                        DEBUG_HAVOK("[HAVOK_MATCH_CAND] ep=0x%I64X mot_vt=0x%I64X dist=%.2fm ref=(%.2f,%.2f,%.2f)",
                                    out_entities[i].entity_ptr, ent_mot, sqrtf(dist2), refPos[0], refPos[1], refPos[2]);
                    }

                    if (dist2 <= bestDist2) {
                        bestDist2 = dist2;
                        best_ep = out_entities[i].entity_ptr;
                        out_entities[i].is_local = TRUE;
                    }
                }
            }
        }
    }

    static UINT64 s_lastLogEp = 0;
    if (best_ep >= 0x10000ULL) {
        if (best_ep != s_lastLogEp) {
            DEBUG_HAVOK("Havok_GetEntities: Mapped local player RigidBody to 0x%I64X (motion_vt match + 2m crosscheck)", best_ep);
            s_lastLogEp = best_ep;
        }
        g_HavokState.local_entity_ptr = best_ep;
        float pos[3] = {0};
        BYOVD_LOCK();
        BYOVD_ReadVA_NoCache(cr3, best_ep + RB_OFF_COORDS, pos, 12);
        BYOVD_UNLOCK();
        if (pos[0] != 0.0f || pos[1] != 0.0f || pos[2] != 0.0f) {
            g_HavokState.local_pos.x = pos[0];
            g_HavokState.local_pos.y = pos[1];
            g_HavokState.local_pos.z = pos[2];
        }
        for (int i = 0; i < total_results; i++) {
            if (out_entities[i].entity_ptr == best_ep) {
                out_entities[i].is_local = TRUE;
            }
        }
    } else {
        if (s_lastLogEp != 0) {
            DEBUG_HAVOK("Havok_GetEntities: Local player RigidBody reference lost (unmounted or dead)");
            s_lastLogEp = 0;
        }
        g_HavokState.local_entity_ptr = 0;
        g_HavokState.local_pos.x = g_HavokState.local_pos.y = g_HavokState.local_pos.z = 0.0f;
    }

    return total_results;
}

UINT64 Havok_GetLocalPlayerEp(void)
{
    return g_HavokState.local_entity_ptr;
}

BOOL Havok_GetLocalPlayerPos(float out[3])
{
    if (!out) return FALSE;
    if (g_HavokState.local_entity_ptr >= 0x10000ULL) {
        out[0] = g_HavokState.local_pos.x;
        out[1] = g_HavokState.local_pos.y;
        out[2] = g_HavokState.local_pos.z;
        return TRUE;
    }
    return TigerList_ReadLPPosition(out);
}
