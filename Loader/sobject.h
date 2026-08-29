/*===========================================================================
 * sobject.h — Destiny 2 Tiger ECS / SObject reference
 *
 * Fontes:
 *   - leaks.txt       : descrição geral + pseudocódigo do handle resolver
 *   - IDA reversal    : sub_D288C0, sub_CA5960, sub_142CC00, sub_E09A20
 *   - Diagnostics     : runs de fly.c (logs confirmados em campo)
 *
 * IMPORTANTE: offsets são relativos ao d2base (GetDestiny2Base()).
 * O game re-randomiza salts dos handles a cada reinício mas a estrutura
 * não muda entre builds da mesma versão.
 *===========================================================================*/

#pragma once
#include <stdint.h>

/*---------------------------------------------------------------------------
 * 1. STRUCT CONSTANTS
 *--------------------------------------------------------------------------*/

#define SOBJ_STRIDE             0xE0        /* hardcoded, confirmado         */
#define SOBJ_MAX                4096        /* hardcoded, confirmado         */

/* ── TigerList — confirmed behaviour (runtime logs + CE, May 2026) ──────────
 *
 * Always 16 slots, stride 0x4F20.  Only player-type entries; no mobs/AI.
 *
 *   SLOT (entVA = arrPtr + i * 0x4F20)
 *     +0x004  u32   entity handle — passed to esp_datum_resolve() for alive
 *                   check.  Returns non-zero component ptr if alive.
 *     +0x024  u32   Tiger handle copy (reference only; same as +0x004)
 *     +0x848  float  revive timer (writable)
 *     +0x4716 byte   grenade ability charge (writable)
 *     +0x9D4  u8[]  encrypted display name (all slots including LP)
 *     +0xA24  u32   team ID plaintext (0 or 1; >10 treated as unknown)
 *     +0xA94  u32   team ID mirror
 *
 * Deduplication: the same handle can appear in two consecutive slots —
 * skip any slot whose handle was already committed in the current pass.
 *
 * Positions for non-LP slots are NOT stored in the TigerList.
 * They come from Schindler's List (SL), at SL entry[i]+0x20 (float[3],
 * centre-of-mass, same reference as the Havok rigid body).
 *
 * Resolution path:
 *   d2base + TLIST_DIRECT_PTR_OFF → ptr to PObjects container
 */

/* ── All offsets below are from entVA = arrPtr + i*TLIST_STRIDE_BYTES ── */
#define TLIST_ENT_PLAYERDEF_HDL 0x004      /* u32 handle; passed to esp_datum_resolve() */
#define TLIST_ENT_SOBJECT_HDL   0x084      /* u32 SObject handle */
#define TLIST_ENT_HANDLE        TLIST_ENT_PLAYERDEF_HDL   /* u32 handle; passed to esp_datum_resolve() — 0 on LP slot */
#define TLIST_SLOT_ENTITY_HDL   0x024      /* u32 Tiger handle (reference only) */
#define TLIST_ENT_REVIVE        0x848      /* float revive timer (slot, writable)  */


#define TLIST_ENT_ABILITY_GRENADE 0x4716   /* grenade charge (slot, writable)      */
#define TLIST_STRIDE_BYTES      0x4F20     /* per-slot stride                      */
#define TLIST_ENT_ENC_NAME      0x9D4      /* u8[] encrypted display name (all slots, incl. LP) */
#define TLIST_ENT_TEAM_A        0xA24      /* u32 team ID plaintext (0/1)          */
#define TLIST_ENT_TEAM_B        0xA94      /* u32 team ID mirror                   */
#define TLIST_INV_ANCHOR_OFF    0x1348     /* anchor blob @ INVENTORY+this   */
#define TLIST_INV_ANCHOR_BACK   0x5B2B74   /* root = anchor - this           */



/*---------------------------------------------------------------------------
 * Player action-state type-hash IDs (from leaked g_ActionChecks[]).
 * Read the action component (walk the sobject component chain) and compare
 * the type_ref field against these values to gate fly/movement writes.
 *--------------------------------------------------------------------------*/
#define ACT_SLIDING     0x80c3b982u
#define ACT_MANTLING    0x80a5a1aeu   /* also 0x80a5a1a3 — two mantling variants */
#define ACT_MANTLING2   0x80a5a1a3u
#define ACT_GHOST       0x80c3b5a9u   /* Ghost in hand */
#define ACT_EMOTING     0x80a5a1acu
#define ACT_ICARUS_DASH 0x80c375f9u

/*---------------------------------------------------------------------------
 * 2. SOBJECT LAYOUT
 * Cada entrada no array SObject tem stride 0xE0 (224 bytes).
 *--------------------------------------------------------------------------*/

#define SOBJ_OFF_TYPE           0x08    /* uint8_t: ObjectType type          */
#define SOBJ_OFF_ALIVE          0x09    /* uint8_t: 0=dead, else alive       */
#define SOBJ_OFF_COMP_HANDLE    0x4C    /* uint32_t: Handle classHandle      */
#define SOBJ_OFF_ENC_POS        0xC0    /* float[3]: position (Vector4Encrypted pos) */
#define SOBJ_OFF_ENC_SCALE      0xDC    /* uint32_t: encrypted float scale   */

/* ── Entity type/flag classification ────────────────────────────────────── */
/* type_flags byte at +0x06 (high nibble) — entity classification helpers   */
#define SOBJ_TYPEFLAG_PLAYER    0x0Cu   /* player entity type                */
#define SOBJ_TYPEFLAG_PVEMOB    0x03u   /* PvE mob/enemy entity type         */

/* Inline helpers for instant_size.c and monster_scale.c */
static __inline int SObject_IsPlayer(uint8_t type_flags, uint8_t type)
{
    (void)type_flags;
    return (type == SOBJ_TYPEFLAG_PLAYER);
}

static __inline int SObject_IsPvEEnemy(uint8_t type_flags, uint8_t type)
{
    (void)type;
    return (type_flags == SOBJ_TYPEFLAG_PVEMOB);
}

/* Derive XOR key from current encrypted scale value.
 * The key is the upper 16 bits of the encrypted float XOR'd with a round
 * constant. In practice, store current_enc and reconstruct from known
 * plaintext when available; here we use a lightweight heuristic. */
static __inline uint32_t SObject_DeriveScaleKey(uint32_t current_enc)
{
    /* Round-trip key: derive key such that (current_enc ^ key) gives a
     * plausible IEEE754 float. We assume the engine stores:
     *   enc = plain ^ key   where key = high16(enc) replicated to 32 bits. */
    uint32_t hi = current_enc >> 16;
    return (hi << 16) | hi;
}

/* Tipos de entidade observados:
 *   0x010B = single live entity (tipo principal do pool loader)
 *   0x0111 = entidades de sistema ativas (loader/UI)
 *   0x0103 = visto em diagnósticos anteriores
 *   0xFEEF = slot livre/free-list (magic marker)
 * O tipo do player entity ainda não foi confirmado neste pool. */


/*---------------------------------------------------------------------------
 * 3. PLAYER_OBJECT STRUCT (componente retornado por GetComponent)
 * Obtido de reverse engineering compartilhado.
 * display_name @ +0x98 CONFIRMADO como alvo do namechanger.
 *--------------------------------------------------------------------------*/

#pragma pack(push, 1)
typedef struct {
    float x, y, z;
} Vector3_t;

typedef struct {
    uint8_t  pad_0000[208];     /* 0x0000 */
    Vector3_t position;         /* 0x00D0 — posição da bone (tecnicamente vec4, W ignorado) */
    uint8_t  pad_00DC[4];       /* 0x00DC */
    Vector3_t rotation;         /* 0x00E0 — rotação da bone */
} Bone_t;

typedef struct {
    void*    vtable;            /* 0x0000 — ponteiro de vtable (aponta para d2base) */
    uint32_t instance_id;       /* 0x0008 */
    uint8_t  pad_000C[132];     /* 0x000C */
    int32_t  ent_index;         /* 0x0090 */
    int32_t  enc_team_id;       /* 0x0094 — encriptado */
    char     display_name[64];  /* 0x0098 — GAMERTAG ASCII null-terminated ← ALVO */
    uint8_t  pad_00D8[128];     /* 0x00D8 */
    uintptr_t enc_bone_base;    /* 0x0158 — encriptado */
    uint32_t enc_bone_count;    /* 0x0160 — encriptado */
    uint8_t  pad_0164[4];       /* 0x0164 */
    uintptr_t enc_dirty_bones;  /* 0x0168 — encriptado */
    uint32_t enc_dirty_bones_count; /* 0x0170 — encriptado */
    uint8_t  pad_0174[4];       /* 0x0174 */
    uint8_t  pad_0178[200];     /* 0x0178 */
    uint64_t enc_last_vis_time; /* 0x0240 — encriptado */
    uint8_t  pad_0248[420];     /* 0x0248 */
    /* sizeof ≈ 0x3EC (1004 bytes) */
} PlayerObject_t;
#pragma pack(pop)

#define PLR_OFF_DISPLAY_NAME    0x98
#define PLR_DISPLAY_NAME_LEN    64

/* HP e Shield do player — offsets NEGATIVOS a partir do sobject base.
 * Válidos APENAS para players (is_player == TRUE).
 * Inimigos usam offsets diferentes (ainda não mapeados).
 * Ambos são u32 encriptados → ESP_DecryptFloat(key4).
 *   sobject - 0x70C = HP
 *   sobject - 0x710 = Shield                                                */
#define PLR_OFF_ENC_HP          (-0x70C)
#define PLR_OFF_ENC_SHIELD      (-0x710)

/*---------------------------------------------------------------------------
 * 4. TIGER HANDLE TABLE / DATUM SYSTEM
 * Baseado em leaks.txt + confirmado em campo.
 *--------------------------------------------------------------------------*/

/* Chunk descriptor (64 bytes cada, indexado por cidx << 6):
 *   cbase = TIGER_HANDLE_TABLE + cidx * 64
 *   +0x00  : padding / flags
 *   +0x08  : abase (uint64) — base do array de datum entries
 *   +0x10  : type_desc_base (uint64) — pool de TYPE DESCRIPTORS;
 *            entry[idx] + 0x98 = component type name string
 *   +0x18  : segunda pool (função ainda desconhecida)
 *   +0x20  : ...
 *   +0x28  : ponteiro para código do jogo
 *   +0x30  : esz (int32) — stride de cada datum entry (ex: 32 para loader pool)
 *   +0x34  : bm2 (int32) — máscara para pointer correction
 *   +0x38  : flags/misc
 *
 * Pool loader (cidx=974, CONFIRMADO EM CAMPO):
 *   abase  = 0x6F361900 (muda por run mas cidx=974 constante)
 *   esz    = 32
 *   type_desc +0x98: "loader", "ui batch tag loader",
 *                    "global resource unload", "bootstrap_patchable"
 *   → Este pool NÃO contém player entities. */

typedef struct {
    uintptr_t entry_base;   /* +0x00 relativo a v10+8: abase do array       */
    uint8_t   pad[0x20];    /* +0x08 padding                                */
    uint32_t  stride;       /* +0x28 stride por entry                       */
    int32_t   adj;          /* +0x2C máscara de ajuste (bm2)                */
} DatumRowData_t;

/* datum_resolve(h):
 *   1. Rejeita h==0 ou h==0xFFFFFFFF
 *   2. salt = h >> 13
 *   3. cidx = salt & ((salt | 0xFFC0000) >> 18)
 *      NOTA: cidx > 0x15000 → rejeita (guard do leak)
 *   4. cbase = TIGER_HANDLE_TABLE + cidx * 64
 *   5. row   = *(DatumRowData*)(cbase + 8)
 *   6. v11   = row.entry_base + row.stride * (h & 0x1FFF)   ← dirty ptr
 *   7. mask  = *(uint64*)(v11 + 8)                           ← bm1
 *   8. ptr   = v11 - (mask & (uint64)(int64)row.adj)         ← real ptr
 *   9. return ptr > 0x1000000 ? ptr : 0
 *
 * Implementado em lists.h como DecryptTicket(cr3, ticket). */

/*---------------------------------------------------------------------------
 * 5. COMPONENT CHAIN WALK (from leaks.txt)
 * Cada SObject tem um componente acessível via comp_handle @ +0x4C.
 * A cadeia é uma linked list de comportamentos/componentes.
 *--------------------------------------------------------------------------*/

/* Layout de cada nó da chain (dentro do datum entry):
 *   +0x00  : flags (uint16)
 *   +0x02  : type_ref (uint16)
 *   +0x04  : match_id (uint32)
 *   +0x08  : schema_h (uint32) — hash do schema do componente
 *   +0x0C  : data_h (uint32)   — handle para os dados reais do componente
 *   +0x10  : state (uint8)
 *   +0x18  : next_h (uint32)   — handle do próximo componente na chain
 *
 * Walk (max 64 iterações para segurança):
 *   h = *(u32*)(sobject + 0x4C)   // comp_handle
 *   while h valid:
 *     raw = datum_resolve(h)
 *     // lê flags, type_ref, data_h, next_h do raw
 *     data_ptr = ESP_DecryptPtr(raw)   // se data_h é um ptr encriptado
 *     h = *(u32*)(raw + 0x18)          // avança na chain
 *
 * NOTA CAMPO: datum entries do pool loader (cidx=974) têm:
 *   +0x00 = FEEF0003 (magic free-list tag nos 4 bytes baixos)
 *   +0x08..+0x18 = zeros
 *   Nenhum data_h válido foi encontrado neste pool. */

/*---------------------------------------------------------------------------
 * 6. BONE SYSTEM (from leaks.txt)
 * Bones ficam dentro de um componente específico da chain.
 *--------------------------------------------------------------------------*/

/* comp + 0x180 → primeiro Bone_t, stride = 0x20
 * for i in range(bone_count):
 *     bone_addr = comp + 0x180 + i * 0x20
 *     position  = *(Vector3*)(bone_addr + 0x10)  → X, Y, Z */


/*---------------------------------------------------------------------------
 * 7. KEY AOB PATTERNS
 * Usadas para localizar as chaves de decriptação em runtime via scan.
 *--------------------------------------------------------------------------*/

/* PointerManager keys (para ESP_DecryptPtr):
 *   Key1: E8 ?? ?? ?? ?? 8B C8 BD ?? ?? ?? ??   → imm32 @ +8
 *   Key2: E8 ?? ?? ?? ?? 8B D8 BD ?? ?? ?? ??   → imm32 @ +8
 *   Key3: E8 ?? ?? ?? ?? 8B F8 BA ?? ?? ?? ??   → imm32 @ +8
 *   Key4: E8 ?? ?? ?? ?? 48 63 D0 BE ?? ?? ?? ?? → imm32 @ +9
 *
 * cff_decrypt_float key sig (para HP float):
 *   E8 ?? ?? ?? ?? 33 E8 E8
 *
 * datum_table sig (para TIGER_HANDLE_TABLE):
 *   48 8B 05 ?? ?? ?? ?? BD
 *
 * Schindler's List AOB (encontrado mas NÃO é lista de player handles):
 *   48 8D 2D ?? ?? ?? ?? 8B F2   → LEA RCX,[rip+disp32]
 *   root = resolved_va + 0x8
 *   Encontrado: va=0x7FF67F360ACB, root=0x7FF680A8D1E8
 *   Conteúdo: struct com flags/counts (0x200, 0x20, 0x01), NÃO handles */

/*---------------------------------------------------------------------------
 * 8. POINTER DECRYPTION
 *--------------------------------------------------------------------------*/

/* PointerManager::Decrypt (from leaks.txt — implementação completa em esp.h)
 * Lê uint64 em encryptedAddress, aplica state machine com key1/key2/key3.
 * Usado para transformar datum entries em ponteiros reais de componente.
 *
 * NOTA CAMPO: todos ESP_DecryptPtr retornaram 0x0 para o pool loader (cidx=974).
 * O pool loader não usa pointer encryption (datum entries são tags simples). */

/* cff_decrypt_float (from leaks.txt — implementado em esp.h como ESP_DecryptFloat)
 * Decripta um float encriptado (usado para HP).
 * NÃO é a decriptação de posição (enc_pos usa chaves diferentes).
 *
 * Key sig: E8 ?? ?? ?? ?? 33 E8 E8 (key4 @ offset +9 do match) */

/*---------------------------------------------------------------------------
 * 9. POSIÇÃO ENCRIPTADA (enc_pos @ SObject+0xD0)
 * A decriptação de coordenadas usa um algoritmo/chaves DIFERENTES do
 * cff_decrypt_float (key4) e do PointerManager::Decrypt (key1-3).
 *
 * Instrução de leitura encontrada: movups xmm6,[reg+0x000000D0]
 * Candidatos de alta frequência (count=740 no CE):
 *   7FF6DB83C1DC   movups xmm6,[rcx+000000D0]
 *   7FF6DB83C2BB   movups xmm6,[rcx+000000D0]
 *
 * Segundo o amigo: "debug the encrypted coord and you will find 2 calls
 * with keys inside them" — essas keys decriptam a Schindler's List,
 * NÃO são keys de posição para o sobj scan.
 *
 * Padrão observado nos valores enc_pos:
 *   X-component: byte alto = 0xE1 (maioria das entidades) ou 0xFF (loader pool)
 *   Z-component: byte alto = 0x78 (todas entidades confirmadas)
 *   Y-component: varia bastante
 *   Samples estáticos (não mudam entre runs — objetos fixos):
 *     enc=(E111618D,61992A63,782DB02D)
 *     enc=(E1104CC2,6191B713,7823475E)
 *     enc=(E15AE418,E1C4D049,79DB5781) */

/*---------------------------------------------------------------------------
 * 10. IDA REVERSAL — sub_D288C0 (player component function)
 * Analisa componentes do player local. Acessos relevantes:
 *
 *   sub_CA5960  = GetComponent(entity_handle, &component_type_dword, 0)
 *                 → retorna ptr para componente; +8 = state byte
 *   sub_142CC00 = GetLocalPlayerHandle() → handle u32 para v44
 *   sub_E09A20  = component data accessor(datum_entry, &type) → data ptr
 *   sub_332A30  = validação/check do datum entry
 *   sub_5427C0  = get count from TigerList struct
 *   sub_12E390  = iterator init(base, count)
 *   sub_D25270  = player state check (retorna bool)
 *
 * Fórmula de datum indexing (do sub_D288C0):
 *   v5 = qword_27C41D8 + qword_27C41E0 * (v44 & 0x1FFF)
 *      = TLIST_ABASE + TLIST_STRIDE * (handle & 0x1FFF)
 *   v35 = *(uint64*)(v5 + 48)     ← 48 = 0x30, lê do datum entry+0x30
 *   v4  = *(uint32*)sub_E09A20(v5, &v42)
 *
 * g_ActionChecks[] (action type hashes):
 *   0x80c3b982 = ACT_SLIDING
 *   0x80a5a1ae = ACT_MANTLING
 *   0x80a5a1a3 = ACT_MANTLING (variante)
 *   0x80c3b5a9 = ACT_GHOST
 *   0x80a5a1ac = ACT_EMOTING
 *   0x80c375f9 = ACT_ICARUS_DASH
 *
 * NOTA: off_29E2E60 (d2base+0x29E2E60) → ptr (0x7FF6820A7FA0) → struct C++
 *   +0x00: 0x80807B1E (component type hash, prefix 0x8080 = schema)
 *   +0x08: 0x7FF68281CC20 (vtable/function ptr no binary)
 *   ... (todos são function pointers — não é um handle de entidade)
 *   Nenhum dos 16 DWORDs retornou DecryptTicket válido. */

/*---------------------------------------------------------------------------
 * 11. DIAGNÓSTICOS CONFIRMADOS EM CAMPO
 *--------------------------------------------------------------------------*/

/* ep (Havok RigidBody local player):
 *   ep = 0x1088BD80 / 0x1089BD80 (muda por run, ~0x108xxxxx)
 *   ep+0x030 = xformVA (transform matrix)
 *   ep+0x040 = {low=0xE0 (SOBJ_STRIDE), high=0x4C (SOBJ_OFF_COMP_HANDLE)}
 *   ep+0x090 → ponteiro para estrutura auxiliar
 *   ep+0x100 → ponteiro para estrutura auxiliar 2
 *   ep+0x1C0 = coords float[3] (DECRIPTADOS, usados pelo fly)
 *   ep+0x230 = velocity float[3] (escrita pelo fly)
 *   ep+0x148 = 0x0000000001030000 (type code 0x0103 visto no entity list)
 *
 * hkpWorld = 0x10845250 / 0x10855250 (muda por run)
 *
 * TIGER_HANDLE_TABLE = 0x746EF80 / 0x747EF80 (muda por run)
 *
 * Coordenadas do fly funcionam corretamente via ep+0x1C0.
 * Alive check via coordenadas: all-zero ou NaN = player morreu.
 *
 * Camera:
 *   camBase = 0x6D6191B0 / 0x6D6291B0 (muda por run)
 *   camBase+0x18 = yaw (float)
 *   camBase+0x1C = pitch (float)
 *   Encontrado via AOB cam sig scan.
 *
 * Tiger Handle Table chunks em campo:
 *   cidx=974: esz=32, abase≈0x6F361900 — LOADER/UI pool
 *             type names: "loader", "ui batch tag loader",
 *                         "global resource unload", "bootstrap_patchable"
 *   Todos os handles do entity list (0x27BE768) mapeiam para cidx=974.
 *   → O entity list em 0x27BE768 é EXCLUSIVAMENTE o loader pool.
 *   → Player entities estão em outro pool/lista ainda não localizado. */

/*---------------------------------------------------------------------------
 * 12. PRÓXIMOS PASSOS
 *--------------------------------------------------------------------------*/

/* HTAB scan (fly.c Fly_HC):
 *   Escaneia cidx 0..1023 procurando chunks com esz >= 0x80.
 *   Chunks com esz grande (>= 0x200) são candidatos para player_object.
 *   Para cada chunk: lê type name e escaneia primeiras 32 entries por
 *   ASCII em +0x98 (display_name).
 *
 * Quando encontrado o cidx correto:
 *   1. Ler abase e stride do chunk descriptor
 *   2. Iterar entries: datum_resolve → real_ptr
 *   3. real_ptr + 0x98 = display_name (PlayerObject_t.display_name)
 *   4. Para namechanger: BYOVD_WriteVA(cr3, real_ptr+0x98, newname, len)
 *
 * Schindler's List keys (método alternativo — pendente):
 *   Requer debugar movups xmm6,[reg+0xD0] no CE para encontrar as
 *   2 CALLs com imm32 keys que decriptam as entradas da Schindler's List. */
