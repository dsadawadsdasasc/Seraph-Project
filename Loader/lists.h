#pragma once
#include "ThemidaSDK.h"
#include "local_player.h"
#include "xor_strings.h"
#include "havok.h"
/* lists.h -- Havok physics entity list traversal
 *
 * AOB to resolve hkpWorld pointer:
 *   48 8B 0D ? ? ? ? C1 E8
 *   Instrução: mov rcx, [rip+disp32]  (RIP-relative MOV, 7 bytes)
 *   Resolver:  hkpWorld_VA = instr_VA + 7 + *(INT32*)(instr_VA + 3)
 *              hkpWorld    = *(UINT64*)hkpWorld_VA
 *
 * Layout dentro de hkpWorld:
 *   +0x40  IslandList0  { uintptr_t list; uint32_t count; uint32_t pad; }
 *   +0x50  IslandList1  { uintptr_t list; uint32_t count; uint32_t pad; }
 *   island_ptr[i] + 0x68 -> EntityList { uintptr_t list; uint32_t count; uint32_t pad; }
 *   entity_ptr           -> RigidBody (offsets abaixo)
 *
 * RigidBody offsets confirmados:
 *   0x000  vtable
 *   0x018  p_hkpWorld
 *   0x020  p_Collidable
 *   0x150  p_Motion
 *   0x1C0  coords   (Vector3: x,y,z + padding float em 0x1CC)
 *   0x230  velocity (Vector3: x,y,z + padding float em 0x23C)
 *
 * Uso:
 *   1. Chamar Havok_Init() apos attach para resolver hkpWorld e HkpMotionType via AOB.
 *   2. Chamar Havok_GetEntities() a cada tick para obter lista de entidades proximas.
 *   3. g_HavokState.local_entity_ptr contem o ponteiro do jogador local (menor distancia).
 */

#include <windows.h>
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "aob_patterns.h"

/* ── Capacidades ─────────────────────────────────────────────────────────── */
#define HAVOK_MAX_ISLANDS   0x1388u  /* kMaxCount: limite de islands por lista */
#define HAVOK_MAX_ENTITIES  256u     /* cap de entidades acumuladas por lista  */
#define HAVOK_MAX_RESULTS   256u     /* limite de HavokEntity retornados       */

/* ── Offsets dentro de hkpWorld ──────────────────────────────────────────── */
#define HAVOK_OFF_ISLAND_LIST0  0x40u
#define HAVOK_OFF_ISLAND_LIST1  0x50u
#define HAVOK_OFF_ENTITY_LIST   0x68u

/* hkpWorld has MORE than two simulation-island lists. Tiger Engine (and the
 * underlying Havok) typically maintain:
 *   m_activeSimulationIslands   (LIST0 0x40)
 *   m_inactiveSimulationIslands (LIST1 0x50)
 *   m_dirtySimulationIslands    (candidate)
 *   m_fixedIsland               (candidate)
 *   m_newIslandList             (candidate — newly-created islands not yet
 *                                merged into active/inactive; RESPAWNED PLAYER
 *                                likely sits here briefly after the cooldown
 *                                ends, which is why Step 1 can't find E2A0
 *                                while only 0x40/0x50 are scanned)
 * All of these follow the same hkArray layout (ptr@+0, count@+8), so we can
 * probe a short sequence of offsets after 0x50 and keep the ones that look
 * like valid list headers. */
#define HAVOK_EXTRA_LIST_OFFSETS_MAX  8u

/* ════════════════════════════════════════════════════════════════════════════
 * ATUALIZAÇÃO SEMANAL DO DESTINY 2 — O QUE MUDAR QUANDO O FLY PARAR
 * ════════════════════════════════════════════════════════════════════════════
 *
 * A Bungie atualiza o D2 toda terça-feira. A cada update, o compilador muda
 * o layout interno das classes Havok, quebrando os offsets abaixo.
 *
 * PASSO A PASSO após um update:
 *
 * 1. ATUALIZAR K_LP_VT_OFF (offset do objeto hkpCharacterMotion em body+0x150)
 *    - Zerar K_LP_VT_OFF temporariamente para usar Step 3 (unique-vtable)
 *    - No log, procurar "UNIQUE-VT" e anotar o vtable reportado
 *    - Ler *(d2base + offset) in-process para encontrar o novo K_LP_VT_OFF
 *      (o offset é tal que d2base+offset == valor em body+0x150 do jogador)
 *    - Colocar o novo valor em K_LP_VT_OFF e recompilar
 *
 * 2. VERIFICAR RB_OFF_COORDS (atualmente 0x1C0)
 *    - No log STRUCT DIAG, olhar o ent do jogador
 *    - Se "coords@+0x1C0" NÃO aparecer ou d2 for alto, olhar qual offset
 *      tem d2 < 10.0 — esse é o novo RB_OFF_COORDS
 *    - Atualizar RB_OFF_COORDS abaixo e recompilar
 *
 * 3. VERIFICAR RB_OFF_VELOCITY (atualmente 0x230)
 *    - Após o fly resolver o jogador, olhar o log "FIRST TICK vel scan"
 *    - Se o fly não mover o jogador mas VELVERIFY passar (read==wrote),
 *      o offset 0x230 está sendo sobreescrito pelo engine — tentar outros
 *      candidatos do vel scan (procurar mag que oscila ao correr)
 *    - Atualizar RB_OFF_VELOCITY abaixo e em fly.c (FLY_VEL_X)
 *
 * 4. SE O FLY NÃO RESOLVER O JOGADOR (ep=0x0 nos logs):
 *    - Confirmar que K_LP_VT_OFF correto (passo 1)
 *    - Confirmar que RB_OFF_COORDS correto (passo 2)
 *    - Se ainda falhar: zerar K_LP_VT_OFF — Step 3 (unique-vtable) aprende
 *      o vtable automaticamente a partir do único vtable distinto no scan
 *
 * HISTÓRICO DE VALORES:
 *   build 28/06/2026 : K_LP_VT_OFF = 0x21AFAB8  RB_OFF_COORDS = 0x1C0
 *   build 05/05/2026 : K_LP_VT_OFF = 0x12CB100  RB_OFF_COORDS = 0x1C0
 *   build pre-05/2026: K_LP_VT_OFF = 0x12BE2A0  RB_OFF_COORDS = 0x1C0
 * ════════════════════════════════════════════════════════════════════════════ */
extern UINT64 g_local_identity_rva;
extern UINT64 g_character_motion_vtable_rva;

#define K_LP_VT_OFF                 g_character_motion_vtable_rva  /* offset do objeto hkpCharacterMotion em body+0x150; zerar para Step 3 */
#define CHARACTER_MOTION_VTABLE     g_character_motion_vtable_rva
#define LOCAL_IDENTITY              g_local_identity_rva



/* ── API pública ─────────────────────────────────────────────────────────── */
#ifdef __cplusplus
extern "C" {
#endif

/* AOB pattern exposed for FeatureInitThread mega multi-pattern scan. */
extern const UINT8 k_hkp_pat[];
extern const UINT8 k_hkp_mask[];

/* Pre-scan handoff — set by FeatureInitThread mega multi-pattern scan so
 * Havok_Init can skip its own 512 MB scan on warm runs. */
void Havok_SetHkpPreScanResult(UINT64 va);

/* Resolve hkpWorld e HkpMotionType via AOB scan. Chamar após attach. */
BOOL Havok_Init(void);

/* Preenche out_entities (capacidade HAVOK_MAX_RESULTS) com entidades próximas.
 * Retorna número de entidades encontradas. Atualiza g_HavokState.local_entity_ptr. */
int  Havok_GetEntities(HavokEntity *out_entities, int max_out);

/* Limpa estado (chamar no OnDetach). */
void Havok_Reset(void);

/* ── Schindler's List (Tiger Engine player array) ────────────────────────── */

/* AOB: 48 8D 2D ?? ?? ?? ?? 8B F2
 * LEA rcx,[rip+disp32] — resolves to PlayerArray root.
 * list_base = *(PlayerArray + 0x8) */

/* Global handle table base — resolved dynamically via AOB scan */
#ifndef ESP_STATE_DEFINED
#define ESP_STATE_DEFINED
typedef struct {
    UINT64  datum_table_va;    /* resolved datum table VA (from AOB or fallback) */
    UINT32  key1;              /* decryption keys for PointerManager::Decrypt    */
    UINT32  key2;
    UINT32  key3;
    UINT32  key4;              /* decryption key for cff_decrypt_float           */
    BOOL    keys_valid;        /* TRUE once all 4 keys were successfully scanned */
    BOOL    datum_valid;       /* TRUE once datum_table_va is confirmed          */
    UINT64  view_mat_va;       /* W2S: view matrix VA   (4x4 floats, row-major)  */
    UINT64  proj_mat_va;       /* W2S: proj matrix VA   (= view_mat_va + 0x40)   */
    BOOL    matrices_valid;    /* TRUE once view_mat_va resolved successfully    */
    UINT64  g_players_va;      /* VA of g_players encrypted pointer (TigerList)  */
    BOOL    tl_valid;          /* TRUE once g_players_va resolved                */
} EspState;

#ifdef __cplusplus
extern "C" EspState g_EspState;
#else
extern EspState g_EspState;
#endif
#endif

typedef struct {
    UINT32 ticket;       /* 32-bit handle */
    UINT32 pad;
    UINT64 resolved_ep;  /* decrypted RigidBody ptr (or parent obj ptr) */
} PlayerTicket;

extern PlayerTicket g_PlayerTicket;  /* saved player ticket */

/* Resolve PlayerArray via AOB, return list_base. 0 on fail. */
UINT64 PlayerList_Init(void);

/* Given a known ep (from Havok scan), find its Ticket in the player list.
 * Saves result in g_PlayerTicket. Returns TRUE on success. */
BOOL PlayerList_FindTicket(UINT64 known_ep);

/* Use saved g_PlayerTicket to resolve current ep after death/respawn.
 * Returns 0 if ticket not set or resolution fails. */
UINT64 PlayerList_ResolveEp(void);

/* Decrypt a 32-bit Tiger Ticket into a pointer using GLOBAL_HANDLE_TABLE.
 * Returns 0 on failure or if pointer looks invalid. */
UINT64 DecryptTicket(UINT64 cr3, UINT32 ticket);

#ifdef __cplusplus
}
#endif


/* ════════════════════════════════════════════════════════════════════════════
 * IMPLEMENTAÇÃO
 * ════════════════════════════════════════════════════════════════════════════ */
#ifdef LISTS_IMPLEMENTATION

/* ════════════════════════════════════════════════════════════════════════════
 * SCHINDLER'S LIST IMPLEMENTATION
 * ════════════════════════════════════════════════════════════════════════════ */

static UINT64 s_playerArrayBase   = 0;
static UINT64 s_playerArrayRootVA = 0;

#define PLARR_AOB_LEN 9
#define PLARR_SCAN_SIZE 0x20000000ULL  /* 512MB from d2base */

UINT64 PlayerList_Init(void)
{
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2base = GetDestiny2Base();
    if (!cr3 || !d2base) return 0;

    UINT64 table_base_va = g_EspState.datum_table_va;
    if (table_base_va < 0x10000ULL) return 0;

    UINT64 instr_va = d2base + SecureReadStatic(&OBF_OFF_Schindler);
    if (!instr_va) {
        DEBUG_TIGERID("PlayerList_Init: FAIL - secure offset is NULL");
        DEBUG_TICKET("PlayerList_Init: secure offset is NULL");
        return 0;
    }

    /* LEA rcx,[rip+disp32]: instr=7 bytes, disp at offset 3 */
    INT32 disp = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, instr_va + 3, &disp, 4);
    BYOVD_UNLOCK();

    UINT64 arr_root_va = instr_va + 7 + (INT64)disp;  /* VA of PlayerArray struct */
    DEBUG_TIGERID("PlayerList_Init: instr_va=0x%I64X arr_root_va=0x%I64X", instr_va, arr_root_va);
    DEBUG_TICKET("PlayerList_Init: instr_va=0x%I64X arr_root_va=0x%I64X", instr_va, arr_root_va);

    /* list_base = *(arr_root_va + 0x8) */
    UINT64 list_base = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, arr_root_va + 0x8, &list_base, 8);
    BYOVD_UNLOCK();

    if (!list_base) {
        DEBUG_TIGERID("PlayerList_Init: FAIL - list_base is 0");
        DEBUG_TICKET("PlayerList_Init: list_base is 0");
        return 0;
    }

    s_playerArrayRootVA = arr_root_va;
    s_playerArrayBase   = list_base;
    DEBUG_TIGERID("PlayerList_Init: OK list_base=0x%I64X", list_base);
    DEBUG_TICKET("PlayerList_Init: list_base=0x%I64X OK", list_base);
    return list_base;
}

/* Decrypts a 32-bit Tiger Ticket into a pointer using GLOBAL_HANDLE_TABLE.
 * Returns 0 on failure or if pointer looks invalid. */
__declspec(noinline) UINT64 DecryptTicket(UINT64 cr3, UINT32 ticket)
{
    MUTATE_START
    UINT64 _result = 0;
    if (!ticket || ticket == 0xFFFFFFFF) goto _dt_end;

    UINT64 table_base_va = g_EspState.datum_table_va;
    if (table_base_va < 0x10000ULL) goto _dt_end;

    UINT32 salt = ticket >> 13;
    UINT64 idx = (UINT64)(salt & ((salt | 0xFFC0000u) >> 18u));
    if (idx > 0x15000ULL) goto _dt_end;

    UINT64 cbase = table_base_va + idx * 64ULL;
    UINT64 entries = 0;
    UINT32 stride = 0;
    INT32  fixupMask = 0;

    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, cbase + 0x08, &entries, 8);
    BYOVD_ReadVA(cr3, cbase + 0x30, &stride, 4);
    BYOVD_ReadVA(cr3, cbase + 0x34, &fixupMask, 4);
    BYOVD_UNLOCK();

    if (entries < 0x10000ULL || stride == 0) goto _dt_end;

    UINT64 slot = entries + (UINT64)stride * (UINT64)(ticket & 0x1FFFu);
    UINT64 fixup = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, slot + 0x08, &fixup, 8);
    BYOVD_UNLOCK();

    if (!fixup) goto _dt_end;

    UINT64 ptr = slot - (fixup & (UINT64)fixupMask);
    if (ptr > 0x1000000ULL) {
        _result = ptr;
    }

_dt_end:
    MUTATE_END
    return _result;
}


__declspec(noinline) BOOL PlayerList_FindTicket(UINT64 known_ep)
{
    /* MUTATE: ticket-matching scanner.
     * noinline: header-only function, would otherwise be inlined into every
     * caller, scattering MUTATE markers across many TUs. */
    MUTATE_START
    BOOL _plft_result = FALSE;
    if (!known_ep) { DEBUG_TIGERID("PLFT: FAIL known_ep is NULL"); goto _plft_end; }
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) { DEBUG_TIGERID("PLFT: FAIL cr3 is NULL"); goto _plft_end; }

    /* Re-read list_base dynamically (may change on area transition) */
    if (!s_playerArrayRootVA) {
        if (!PlayerList_Init()) { DEBUG_TIGERID("PLFT: FAIL PlayerList_Init failed"); goto _plft_end; }
    }
    UINT64 list_base = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, s_playerArrayRootVA + 0x8, &list_base, 8);
    BYOVD_UNLOCK();
    if (!list_base) { DEBUG_TIGERID("PLFT: FAIL list_base is 0, arr_root_va=0x%I64X", s_playerArrayRootVA); goto _plft_end; }
    s_playerArrayBase = list_base;

    /* Read entry count at arr_root_va + 0x10 (common Tiger layout) */
    UINT32 count = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, s_playerArrayRootVA + 0x10, &count, 4);
    BYOVD_UNLOCK();
    if (!count || count > 32) count = 32; /* player list is tiny, cap at 32 */

    DEBUG_TIGERID("PLFT: scanning %u entries for ep=0x%I64X", count, known_ep);
    DEBUG_TICKET("PlayerList_FindTicket: scanning %u entries for ep=0x%I64X", count, known_ep);

    for (UINT32 i = 0; i < count; i++) {
        /* Try both 4-byte ticket and 8-byte pointer layouts */
        UINT64 raw8 = 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, list_base + (UINT64)i * 8, &raw8, 8);
        BYOVD_UNLOCK();
        DEBUG_TICKET("PlayerList_FindTicket: [%u] raw8=0x%I64X", i, raw8);

        /* Direct pointer match (8-byte layout) */
        if (raw8 == known_ep) {
            g_PlayerTicket.ticket      = (UINT32)i; /* use index as pseudo-ticket */
            g_PlayerTicket.resolved_ep = raw8;
            DEBUG_TIGERID("PLFT: OK DIRECT-PTR [%u] ep=0x%I64X", i, raw8);
            DEBUG_TICKET("PlayerList_FindTicket: DIRECT-PTR [%u] ep=0x%I64X", i, raw8);
            _plft_result = TRUE;
            goto _plft_end;
        }

        /* Try as 4-byte ticket (lower 32 bits) */
        UINT32 ticket = (UINT32)(raw8 & 0xFFFFFFFF);
        if (!ticket || ticket == 0xFFFFFFFF) continue;

        UINT64 resolved = DecryptTicket(cr3, ticket);
        if (!resolved) continue;

        DEBUG_TICKET("PlayerList_FindTicket: [%u] ticket=0x%08X -> 0x%I64X", i, ticket, resolved);

        /* Direct match */
        if (resolved == known_ep) {
            g_PlayerTicket.ticket      = ticket;
            g_PlayerTicket.resolved_ep = resolved;
            DEBUG_TIGERID("PLFT: OK MATCH ticket=0x%08X ep=0x%I64X", ticket, known_ep);
            DEBUG_TICKET("PlayerList_FindTicket: MATCH ticket=0x%08X ep=0x%I64X", ticket, known_ep);
            _plft_result = TRUE;
            goto _plft_end;
        }

        /* Check if resolved is a parent object that contains ep at some offset.
         * Scan first 0x400 bytes for the ep value. */
        for (UINT32 off = 0; off < 0x400; off += 8) {
            UINT64 val = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, resolved + off, &val, 8);
            BYOVD_UNLOCK();
            if (val == known_ep) {
                g_PlayerTicket.ticket      = ticket;
                g_PlayerTicket.resolved_ep = resolved; /* parent obj */
                DEBUG_TIGERID("PLFT: OK INDIRECT ticket=0x%08X parent=0x%I64X ep_off=0x%X", ticket, resolved, off);
                DEBUG_TICKET("PlayerList_FindTicket: INDIRECT ticket=0x%08X parent=0x%I64X ep_off=0x%X",
                          ticket, resolved, off);
                _plft_result = TRUE;
                goto _plft_end;
            }
        }
    }

    DEBUG_TIGERID("PLFT: FAIL no match in %u entries for ep=0x%I64X", count, known_ep);
    DEBUG_TICKET("PlayerList_FindTicket: no match found in %u entries", count);
_plft_end:
    MUTATE_END
    return _plft_result;
}

UINT64 PlayerList_ResolveEp(void)
{
    if (!g_PlayerTicket.ticket) { DEBUG_TIGERID("PLRE: FAIL no saved ticket"); return 0; }
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) { DEBUG_TIGERID("PLRE: FAIL cr3 is NULL"); return 0; }

    UINT64 resolved = DecryptTicket(cr3, g_PlayerTicket.ticket);
    if (!resolved) {
        DEBUG_TIGERID("PLRE: FAIL DecryptTicket(ticket=0x%08X) returned 0", g_PlayerTicket.ticket);
        DEBUG_TICKET("PlayerList_ResolveEp: DecryptTicket failed for 0x%08X", g_PlayerTicket.ticket);
        return 0;
    }

    /* If ticket resolves directly to ep */
    if (resolved == g_PlayerTicket.resolved_ep) {
        DEBUG_TIGERID("PLRE: OK direct ep=0x%I64X", resolved);
        DEBUG_TICKET("PlayerList_ResolveEp: direct ep=0x%I64X", resolved);
        return resolved;
    }

    /* If ticket resolves to parent obj — scan for RigidBody ptr (valid heap address) */
    for (UINT32 off = 0; off < 0x400; off += 8) {
        UINT64 val = 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, resolved + off, &val, 8);
        BYOVD_UNLOCK();
        /* Valid heap address heuristic: 0x100000000 < ptr < 0x800000000 */
        if (val > 0x100000000ULL && val < 0x800000000ULL) {
            /* Verify it looks like a RigidBody: check p_hkpWorld != 0 */
            UINT64 pWorld = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA(cr3, val + RB_OFF_P_HKP_WORLD, &pWorld, 8);
            BYOVD_UNLOCK();
            if (pWorld) {
                DEBUG_TIGERID("PLRE: OK parent=0x%I64X off=0x%X ep=0x%I64X", resolved, off, val);
                DEBUG_TICKET("PlayerList_ResolveEp: parent=0x%I64X off=0x%X ep=0x%I64X", resolved, off, val);
                return val;
            }
        }
    }

    DEBUG_TIGERID("PLRE: FAIL could not find ep in parent=0x%I64X", resolved);
    DEBUG_TICKET("PlayerList_ResolveEp: could not find ep in parent=0x%I64X", resolved);
    return 0;
}

#endif /* LISTS_IMPLEMENTATION */
