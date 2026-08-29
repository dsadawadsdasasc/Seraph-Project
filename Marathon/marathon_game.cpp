#include "marathon_game.h"
#include "byovd.h"
#include "attach.h"
#include "esp.h"
#include <stdio.h>
#include <stdarg.h>
// Zydis removed for AC diagnostic — get_xor_key stubbed to 0
#include <vector>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <cmath>
#include <cstring>

// Definicoes de layout do Marathon
namespace PlayerList {
    constexpr uint32_t STRIDE = 0x360;
    constexpr uint32_t MAX_ENTRIES = 32;
    constexpr size_t   BATCH_SIZE = MAX_ENTRIES * STRIDE;
    constexpr size_t OFF_ENC_BASE_POS_LOW = 0x0F0;
    constexpr size_t OFF_RVA_BASE_POS_LOW = 0x114;
    constexpr size_t OFF_TEAM_ID = 0x120;
    constexpr size_t OFF_ENC_HEAD_POS = 0x160;
    constexpr size_t OFF_RVA_HEAD_POS = 0x184;
    constexpr size_t OFF_ENC_BASE_POS_HIGH = 0x190;
    constexpr size_t OFF_RVA_BASE_POS_HIGH = 0x1B4;
}

namespace PlayerObjects {
    constexpr uint32_t STRIDE = 0x79A0;
    constexpr uint32_t MAX_ENTRIES = 32;
    constexpr size_t OFF_RAW_IDX = 0x004;
    constexpr size_t OFF_HEALTH_HANDLE = 0x74C8;
}

static std::string ReadWString(UINT64 cr3, UINT64 va, size_t max_chars) {
    std::vector<wchar_t> wbuf(max_chars + 1, 0);
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, va, wbuf.data(), max_chars * 2);
    BYOVD_UNLOCK();
    if (!ok) return "";
    
    wbuf[max_chars] = L'\0';
    
    std::string res;
    for (size_t i = 0; i < max_chars && wbuf[i] != L'\0'; i++) {
        wchar_t wc = wbuf[i];
        if (wc >= 32 && wc < 127) {
            res += (char)wc;
        } else {
            res += '?';
        }
    }
    return res;
}/* DIAG: Zydis removed to isolate crash source.
 * If game no longer crashes with this stub → Zydis byte signatures were
 * triggering Marathon AC. Will be replaced with inline mini-disassembler. */
static uint64_t get_xor_key(uintptr_t func_addr) {
    /* DIAG: Zydis removed — stub returns 0 for AC crash isolation.
     * Position decryption will produce zeros until replaced with
     * inline mini-disassembler. */
    (void)func_addr;
    return 0;
}

static std::unordered_map<UINT32, UINT64> g_KeyCache;

extern "C" UINT64 get_cached_xor_key(UINT32 rva, UINT64 image_base) {
    if (rva == 0) return 0;
    auto it = g_KeyCache.find(rva);
    if (it != g_KeyCache.end()) {
        return it->second;
    }
    UINT64 key = get_xor_key(image_base + rva);
    if (key) {
        g_KeyCache[rva] = key;
    }
    return key;
}

// Decrypt Position
static MVector3 DecryptPosition(const uint8_t* data, uint64_t key) {
    uint64_t dec[2];
    std::memcpy(&dec[0], data, 8);
    std::memcpy(&dec[1], data + 8, 8);
    dec[0] ^= key;
    dec[1] ^= key;
    MVector3 v;
    std::memcpy(&v, &dec[0], sizeof(MVector3));
    return v;
}

// Decrypt Name
static inline uint32_t ROL4(uint32_t value, int shift) {
    shift &= 0x1F;
    return (value << shift) | (value >> (32 - shift));
}

static std::string DecryptName(const uint8_t* encrypted, size_t count) {
    std::string result;
    result.reserve(count);
    for (size_t i = 0; i < count && i < 63; i++) {
        uint32_t key = i ? ROL4(2048093534u, i % 31) : 0;
        char c = (char)(91 * (key ^ encrypted[i]));
        if (!c) break;
        result += c;
    }
    return result;
}

// Globals
static MMatrix4x4 g_ViewProjMatrix{};
static MVector3 g_LocalPlayerPos{};
static UINT32 g_LocalPlayerTeam = 0;
static std::vector<MPlayer> g_Players;

// Base RVAs (Dynamic)
UINT64 g_RVA_VpMatrix = 0;
UINT64 g_RVA_DatumTable = 0;
UINT64 g_RVA_PlayerArray = 0;
UINT64 g_RVA_PlayerObjectArray = 0;
UINT64 g_RVA_PlayerObjectArrayDecryptRVA = 0;
UINT64 g_RVA_SObjectList = 0;

static void Marathon_Log(const char* format, ...) {
    char msg[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg) - 1, format, args);
    va_end(args);

    char buf[1280];
    wsprintfA(buf, "[GAME][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    HANDLE hF = CreateFileA("game.log", FILE_APPEND_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, buf, (DWORD)lstrlenA(buf), &w, NULL);
        CloseHandle(hF);
    }
}

BOOL Marathon_Init(void) {
    g_KeyCache.clear();
    g_Players.clear();
    std::memset(&g_ViewProjMatrix, 0, sizeof(g_ViewProjMatrix));
    std::memset(&g_LocalPlayerPos, 0, sizeof(g_LocalPlayerPos));
    g_LocalPlayerTeam = 0;
    return TRUE;
}

BOOL Marathon_GetViewProj(MMatrix4x4* outMatrix) {
    if (!outMatrix) return FALSE;
    std::memcpy(outMatrix, &g_ViewProjMatrix, sizeof(MMatrix4x4));
    return TRUE;
}

BOOL Marathon_GetLocalPos(MVector3* outPos) {
    if (!outPos) return FALSE;
    std::memcpy(outPos, &g_LocalPlayerPos, sizeof(MVector3));
    return TRUE;
}

UINT32 Marathon_GetLocalTeam(void) {
    return g_LocalPlayerTeam;
}

const std::vector<MPlayer>& Marathon_GetPlayers(void) {
    return g_Players;
}

// Get component health/shield via DatumTable (GetComponent)
static void ResolvePlayerHealth(UINT64 cr3, UINT64 datum_tbl, UINT32 health_handle, float* out_hp, float* out_sh) {
    *out_hp = 0.0f;
    *out_sh = 0.0f;
    if (!health_handle) return;

    UINT32 idx = (((health_handle >> 13) | 0xFFC0000u) >> 18) & (health_handle >> 13);
    UINT64 bucket = datum_tbl + (UINT64)idx * 64;

    UINT64 entry_base = 0;
    UINT32 stride = 0;
    INT32 adj = 0;

    if (!BYOVD_ReadVA(cr3, bucket + 8, &entry_base, 8)) return;
    if (!BYOVD_ReadVA(cr3, bucket + 48, &stride, 4)) return;
    if (!BYOVD_ReadVA(cr3, bucket + 52, &adj, 4)) return;
    if (!entry_base || !stride) return;

    UINT64 v11 = entry_base + (UINT64)stride * (health_handle & 0x1FFFu);
    UINT64 mask = 0;
    if (!BYOVD_ReadVA(cr3, v11 + 8, &mask, 8)) return;

    UINT64 hb = v11 - (mask & (UINT64)(INT64)adj);
    if (hb <= 0x10000) return;

    UINT32 e_hp = 0, r_hp = 0;
    UINT32 e_sh = 0, r_sh = 0;

    if (BYOVD_ReadVA(cr3, hb + 0xC98, &e_hp, 4) && BYOVD_ReadVA(cr3, hb + 0xCA4, &r_hp, 4) && e_hp && r_hp) {
        UINT64 key = get_cached_xor_key(r_hp, GetDestiny2Base());
        if (key) {
            UINT32 raw = e_hp ^ (UINT32)key;
            std::memcpy(out_hp, &raw, 4);
        }
    }

    if (BYOVD_ReadVA(cr3, hb + 0xC60, &e_sh, 4) && BYOVD_ReadVA(cr3, hb + 0xC6C, &r_sh, 4) && e_sh && r_sh && e_sh != 0xFFFFFFFFu) {
        UINT64 key = get_cached_xor_key(r_sh, GetDestiny2Base());
        if (key) {
            UINT32 raw = e_sh ^ (UINT32)key;
            std::memcpy(out_sh, &raw, 4);
        }
    }
}

void Marathon_Tick(void) {
    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return;
    if (!g_RVA_VpMatrix || !g_RVA_DatumTable || !g_RVA_PlayerArray || !g_RVA_PlayerObjectArray) return;

    // Sincronizar dados globais do Marathon com o g_EspState
    g_EspState.g_players_va = d2Base + g_RVA_PlayerObjectArray;
    g_EspState.tl_valid = TRUE;
    g_EspState.keys_valid = TRUE;

    // 1. Atualizar ViewProjMatrix
    BYOVD_ReadVA(cr3, d2Base + g_RVA_VpMatrix, &g_ViewProjMatrix, sizeof(MMatrix4x4));

    // 2. Localizar DatumTable base
    UINT64 cam_object_ptr = 0;
    if (!BYOVD_ReadVA(cr3, d2Base + g_RVA_DatumTable, &cam_object_ptr, 8) || !cam_object_ptr) return;
    UINT64 datum_tbl = 0;
    if (!BYOVD_ReadVA(cr3, cam_object_ptr, &datum_tbl, 8) || !datum_tbl) return;

    // Sincronizar DatumTable
    g_EspState.datum_table_va = datum_tbl;
    g_EspState.datum_valid = TRUE;

    static BOOL logged_state = FALSE;
    if (!logged_state) {
        logged_state = TRUE;
        Marathon_Log("g_EspState initialized: players_va=0x%I64X, datum_table_va=0x%I64X", 
                     g_EspState.g_players_va, g_EspState.datum_table_va);
    }

    // 3. Ler PlayerList (posicoes / times)
    UINT64 player_array_base = 0;
    if (!BYOVD_ReadVA(cr3, d2Base + g_RVA_PlayerArray, &player_array_base, 8) || !player_array_base) return;

    std::vector<uint8_t> plist_buf(PlayerList::BATCH_SIZE);
    if (!BYOVD_ReadVA(cr3, player_array_base, plist_buf.data(), PlayerList::BATCH_SIZE)) return;

    // 4. Ler PlayerObjects (nomes / handles de vida)
    UINT64 pobject_base = 0;
    UINT32 decr_rva = 0;
    UINT64 encr_ptr = 0;
    
    if (BYOVD_ReadVA(cr3, d2Base + g_RVA_PlayerObjectArrayDecryptRVA, &decr_rva, 4) && decr_rva &&
        BYOVD_ReadVA(cr3, d2Base + g_RVA_PlayerObjectArray, &encr_ptr, 8) && encr_ptr) {
        
        UINT64 xor_key = get_cached_xor_key(decr_rva, d2Base);
        if (xor_key) {
            UINT64 decrypted_ptr_va = (encr_ptr ^ xor_key) + 8;
            BYOVD_ReadVA(cr3, decrypted_ptr_va, &pobject_base, 8);
        }
    }

    static BOOL logged_pobj = FALSE;
    if (pobject_base) {
        if (!logged_pobj) {
            Marathon_Log("PlayerObjectArray base successfully resolved to: 0x%I64X", pobject_base);
            logged_pobj = TRUE;
        }
    } else {
        static DWORD last_log_fail = 0;
        DWORD now_log = GetTickCount();
        if (now_log - last_log_fail > 10000) { // log a cada 10s em caso de falha
            Marathon_Log("Failed to resolve PlayerObjectArray base pointer.");
            last_log_fail = now_log;
        }
    }

    // Vamos processar a PlayerList e descriptografar as posicoes de todos os 32 slots:
    std::vector<MPlayer> temp_players;
    MVector3 cam_pos = {0};
    
    // A posicao da camera pode ser lida a partir de cam_object_ptr + 0xA00
    MVector3 enc_cam_pos = {0};
    if (BYOVD_ReadVA(cr3, cam_object_ptr + 0xA00, &enc_cam_pos, sizeof(MVector3))) {
        // Posição da câmera pode estar encriptada. Se estiver, a chave está em cam_object_ptr + 0xA14.
        UINT32 cam_decr_rva = 0;
        if (BYOVD_ReadVA(cr3, cam_object_ptr + 0xA14, &cam_decr_rva, 4) && cam_decr_rva) {
            UINT64 key = get_cached_xor_key(cam_decr_rva, d2Base);
            if (key) {
                cam_pos = DecryptPosition((uint8_t*)&enc_cam_pos, key);
            } else {
                cam_pos = enc_cam_pos;
            }
        } else {
            cam_pos = enc_cam_pos;
        }
    }
    
    // No modo read-only, usamos a posicao da camera como a local player pos
    g_LocalPlayerPos = cam_pos;

    for (UINT32 i = 0; i < PlayerList::MAX_ENTRIES; i++) {
        const uint8_t* slot = plist_buf.data() + (i * PlayerList::STRIDE);
        UINT64 ent_ptr = player_array_base + (i * PlayerList::STRIDE);

        UINT32 rva_low = *reinterpret_cast<const UINT32*>(slot + PlayerList::OFF_RVA_BASE_POS_LOW);
        if (!rva_low) continue;

        UINT64 key_low = get_cached_xor_key(rva_low, d2Base);
        if (!key_low) continue;

        MVector3 base_pos_low = DecryptPosition(slot + PlayerList::OFF_ENC_BASE_POS_LOW, key_low);
        
        UINT32 rva_head = *reinterpret_cast<const UINT32*>(slot + PlayerList::OFF_RVA_HEAD_POS);
        MVector3 head_pos = {0};
        if (rva_head) {
            UINT64 key_head = get_cached_xor_key(rva_head, d2Base);
            if (key_head) head_pos = DecryptPosition(slot + PlayerList::OFF_ENC_HEAD_POS, key_head);
        }

        UINT32 rva_high = *reinterpret_cast<const UINT32*>(slot + PlayerList::OFF_RVA_BASE_POS_HIGH);
        MVector3 base_pos_high = {0};
        if (rva_high) {
            UINT64 key_high = get_cached_xor_key(rva_high, d2Base);
            if (key_high) base_pos_high = DecryptPosition(slot + PlayerList::OFF_ENC_BASE_POS_HIGH, key_high);
        }

        // Se coordenadas forem invalidas (0 ou muito fora), pular
        if (base_pos_low.x == 0.0f && base_pos_low.y == 0.0f && base_pos_low.z == 0.0f) continue;

        MPlayer p{};
        p.listIdx = (UINT16)i;
        p.entityPtr = ent_ptr;
        p.teamId = *reinterpret_cast<const UINT32*>(slot + PlayerList::OFF_TEAM_ID);
        p.basePosLow = base_pos_low;
        p.headPos = head_pos;
        p.basePosHigh = base_pos_high;
        
        // Determinar se e o local player (proximidade com a camera)
        float dx = cam_pos.x - base_pos_low.x;
        float dy = cam_pos.y - base_pos_low.y;
        float dz = cam_pos.z - base_pos_low.z;
        float distSq = dx*dx + dy*dy + dz*dz;
        if (distSq < 9.0f) { // Dentro de 3 metros da camera
            p.isLocal = TRUE;
            g_LocalPlayerTeam = p.teamId;
        } else {
            p.isLocal = FALSE;
        }

        // Nomes / HP dinâmicos obtidos via PlayerObject correspondente
        std::string p_name = "Player";
        float p_health = 100.0f;
        float p_shield = 100.0f;

        if (pobject_base) {
            UINT64 slot_addr = pobject_base + (i * PlayerObjects::STRIDE);
            UINT32 playerdef_hdl = 0;
            if (BYOVD_ReadVA(cr3, slot_addr + PlayerObjects::OFF_RAW_IDX, &playerdef_hdl, 4) && playerdef_hdl) {
                // 1. Ler o nome (0x24CA) e número de ID (0x244E) em plaintext (UTF-16)
                std::string name_str = ReadWString(cr3, slot_addr + 0x24CA, 32);
                std::string id_str = ReadWString(cr3, slot_addr + 0x244E, 16);
                if (!name_str.empty()) {
                    if (!id_str.empty()) {
                        p_name = name_str + "#" + id_str;
                    } else {
                        p_name = name_str;
                    }
                }
                
                // 2. Ler HP handle e resolver vida via DatumTable
                UINT32 health_hdl = 0;
                if (BYOVD_ReadVA(cr3, slot_addr + PlayerObjects::OFF_HEALTH_HANDLE, &health_hdl, 4) && health_hdl) {
                    ResolvePlayerHealth(cr3, datum_tbl, health_hdl, &p_health, &p_shield);
                }

                // 3. Diagnóstico do SObject/Bone Handle no offset +0x84
                UINT32 diagnostic_hdl = 0;
                if (BYOVD_ReadVA(cr3, slot_addr + 0x84, &diagnostic_hdl, 4)) {
                    static BOOL logged_diag = FALSE;
                    if (diagnostic_hdl && diagnostic_hdl != 0xFFFFFFFFu && !logged_diag) {
                        Marathon_Log("Slot %d: Read potential SObject/Bone handle at +0x84: 0x%X (valid check lower 16: 0x%X)", 
                                     i, diagnostic_hdl, diagnostic_hdl & 0xFFFF);
                        logged_diag = TRUE;
                    }
                }
            }
        }

        p.name = p_name;
        p.health = p_health;
        p.shield = p_shield;

        temp_players.push_back(p);
    }

    g_Players = temp_players;

    static DWORD last_diag_log = 0;
    DWORD now_diag = GetTickCount();
    if (now_diag - last_diag_log > 5000) { // a cada 5 segundos
        last_diag_log = now_diag;
        
        Marathon_Log("=== TELEMETRY DIAGNOSTIC REPORT ===");
        Marathon_Log("Camera Pos: X=%.3f, Y=%.3f, Z=%.3f", g_LocalPlayerPos.x, g_LocalPlayerPos.y, g_LocalPlayerPos.z);
        Marathon_Log("ViewProjMatrix: [0]=%.4f, [5]=%.4f, [10]=%.4f, [15]=%.4f", g_ViewProjMatrix.m[0], g_ViewProjMatrix.m[5], g_ViewProjMatrix.m[10], g_ViewProjMatrix.m[15]);
        Marathon_Log("Active Players in List: %d", (int)g_Players.size());
        
        if (!g_Players.empty()) {
            const auto& p = g_Players[0];
            MVector2 screen_pos = {0};
            BOOL w2s_ok = Marathon_WorldToScreen(p.basePosLow, screen_pos, g_ViewProjMatrix, 1920.0f, 1080.0f);
            Marathon_Log("Sample Player 0: Name='%s', Team=%u, Local=%s", p.name.c_str(), p.teamId, p.isLocal ? "TRUE" : "FALSE");
            Marathon_Log("  BasePos 3D: X=%.3f, Y=%.3f, Z=%.3f", p.basePosLow.x, p.basePosLow.y, p.basePosLow.z);
            Marathon_Log("  HeadPos 3D: X=%.3f, Y=%.3f, Z=%.3f", p.headPos.x, p.headPos.y, p.headPos.z);
            Marathon_Log("  W2S on 1920x1080: Status=%s, ScreenPos: X=%.2f, Y=%.2f", w2s_ok ? "SUCCESS" : "FAILED", screen_pos.x, screen_pos.y);
        }
        Marathon_Log("===================================");
    }
}

BOOL Marathon_WorldToScreen(const MVector3& worldPos, MVector2& screenPos, const MMatrix4x4& vp, float screenWidth, float screenHeight) {
    if (std::isnan(worldPos.x) || std::isnan(worldPos.y) || std::isnan(worldPos.z)) {
        return FALSE;
    }

    float w = worldPos.x * vp.m[3] + worldPos.y * vp.m[7] + worldPos.z * vp.m[11] + vp.m[15];
    if (std::isnan(w) || w < 0.001f) {
        return FALSE; 
    }

    float x = worldPos.x * vp.m[0] + worldPos.y * vp.m[4] + worldPos.z * vp.m[8] + vp.m[12];
    float y = worldPos.x * vp.m[1] + worldPos.y * vp.m[5] + worldPos.z * vp.m[9] + vp.m[13];

    float ndcX = x / w;
    float ndcY = y / w;

    screenPos.x = (screenWidth / 2.0f) * (1.0f + ndcX);
    screenPos.y = (screenHeight / 2.0f) * (1.0f - ndcY);

    return TRUE;
}

extern "C" UINT64 ESP_DecryptPtr(UINT64 cr3, UINT64 enc_field_va) {
    if (!enc_field_va) return 0;
    UINT32 decr_rva = 0;
    UINT64 encr_ptr = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, enc_field_va + 0x14, &decr_rva, 4) &&
              BYOVD_ReadVA(cr3, enc_field_va, &encr_ptr, 8);
    BYOVD_UNLOCK();
    if (!ok || !decr_rva || !encr_ptr) return 0;
    
    UINT64 xor_key = get_cached_xor_key(decr_rva, GetDestiny2Base());
    if (xor_key) {
        return (encr_ptr ^ xor_key) + 8;
    }
    return 0;
}
