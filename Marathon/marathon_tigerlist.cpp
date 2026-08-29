/* marathon_tigerlist.cpp — Marathon specific PObjects (TigerList) slot array reader and bone resolver */
#include "esp.h"
#include "marathon_tigerlist.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "local_player.h"
#include "skeleton.h"
#include <string.h>
#include <math.h>

/* Disable compiler optimization for the entire translation unit. */
#pragma optimize("", off)

#include "debug.h"

static void _write_tl_diag(const char* msg) {
    WriteLogFileEx("seraph_debug.log", msg);
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH - 64);
    if (!n || n >= MAX_PATH - 64) return;
    lstrcatA(path, "\\Downloads\\tigerlist.log");
    HANDLE hF = CreateFileA(path, FILE_APPEND_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, msg, (DWORD)lstrlenA(msg), &w, NULL);
        CloseHandle(hF);
    }
}

static void _tl_log(const char *msg) {
    char buf[640];
    wsprintfA(buf, "[TIGERLIST][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    _write_tl_diag(buf);
}
#define TL_LOG(msg) _tl_log(msg)

static void _tl_log_fmt(const char *fmt, ...) {
    char msg[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg) - 1, fmt, args);
    va_end(args);
    _tl_log(msg);
}

static void _tl_hexdump(const char* label, UINT64 va, const void* data, size_t size) {
    if (!data || size == 0) return;
    _tl_log_fmt("--- HEX DUMP: %s (VA: 0x%I64X, Size: %zu) ---", label, va, size);
    const BYTE* p = (const BYTE*)data;
    char line[128];
    for (size_t i = 0; i < size; i += 16) {
        int off = wsprintfA(line, "+0x%04X | ", (unsigned int)i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) off += wsprintfA(line + off, "%02X ", p[i + j]);
            else off += wsprintfA(line + off, "   ");
        }
        off += wsprintfA(line + off, "| ");
        for (size_t j = 0; j < 16 && (i + j) < size; j++) {
            BYTE c = p[i + j];
            line[off++] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        line[off++] = '\r';
        line[off++] = '\n';
        line[off] = '\0';
        _write_tl_diag(line);
    }
    _tl_log("--- END HEX DUMP ---");
}

/* Module state */
static UINT64 s_encVA     = 0;
static UINT64 s_container = 0;
static BOOL   s_ready     = FALSE;

/* Local Player Bone Component Cache */
static UINT32 s_lpCachedBoneHdl  = 0;
static UINT64 s_lpCachedBoneComp = 0;
static int    s_lpCachedSlotIdx  = -1;

/* Quaternion-rotate v by q, store in out */
static __inline void quat_rotate(const float q[4], const float v[3], float out[3])
{
    float qx = q[0], qy = q[1], qz = q[2], qw = q[3];
    float vx = v[0], vy = v[1], vz = v[2];
    float tx = 2.0f * (qy*vz - qz*vy);
    float ty = 2.0f * (qz*vx - qx*vz);
    float tz = 2.0f * (qx*vy - qy*vx);
    out[0] = vx + qw*tx + (qy*tz - qz*ty);
    out[1] = vy + qw*ty + (qz*tx - qx*tz);
    out[2] = vz + qw*tz + (qx*ty - qy*tx);
}

extern "C" {

static BOOL _validate_skeleton_comp(UINT64 cr3, UINT64 comp, INT32 *cnt_out);

BOOL TigerList_Init(void)
{
    if (s_ready) return TRUE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) {
        _tl_log_fmt("Init FAIL: CR3=0x%I64X, Base=0x%I64X", cr3, d2Base);
        return FALSE;
    }

    /* Reuse VA from esp.h compat state if already resolved */
    if (g_EspState.tl_valid && g_EspState.g_players_va) {
        s_encVA = g_EspState.g_players_va;
        s_ready = TRUE;
        _tl_log_fmt("Init SUCCESS (reused esp_state encVA=0x%I64X)", s_encVA);
        return TRUE;
    }

    static DWORD lastTry = 0;
    DWORD now = GetTickCount();
    if (lastTry && (now - lastTry) < 2000) return FALSE;
    lastTry = now;

    UINT8 pat[]  = {0x12, 0xD1, 0x47, 0x5A, 0x5A, 0x5A, 0x5A, 0x16, 0xD1, 0xA3};
    UINT8 mask[] = {0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5};
    for (int i = 0; i < 10; i++) { pat[i] ^= 0x5A; mask[i] ^= 0x5A; }
    UINT64 match = BYOVD_ScanPatternTextRaw(cr3, d2Base, pat, mask, 10);
    if (!match) { TL_LOG("Init: AOB not found"); return FALSE; }

    _tl_log_fmt("Init: AOB Match at 0x%I64X", match);

    INT32 disp = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, match + 3, &disp, 4);
    BYOVD_UNLOCK();

    s_encVA = match + 7 + (INT64)disp;
    s_ready = (s_encVA >= 0x10000ULL);

    _tl_log_fmt("Init: Resolved s_encVA=0x%I64X (disp=0x%X, ready=%d)", s_encVA, disp, (int)s_ready);

    if (s_ready) {
        g_EspState.g_players_va = s_encVA;
        g_EspState.tl_valid = TRUE;
    }
    return s_ready;
}

BOOL  TigerList_IsReady(void) { return s_ready; }

void TigerList_Reset(void)
{
    s_encVA     = 0;
    s_container = 0;
    s_ready     = FALSE;
    s_lpCachedBoneHdl  = 0;
    s_lpCachedBoneComp = 0;
    s_lpCachedSlotIdx  = -1;
}

UINT64 TigerList_GetContainer(void)
{
    if (!s_ready) return 0;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return 0;

    static DWORD s_lastTick = 0;
    DWORD now = GetTickCount();
    if (s_container >= 0x10000ULL && (now - s_lastTick < 500))
        return s_container;

    s_container = ESP_DecryptPtr(cr3, s_encVA);
    s_lastTick  = now;
    _tl_log_fmt("GetContainer: Decrypted container=0x%I64X from encVA=0x%I64X", s_container, s_encVA);
    if (s_container < 0x10000ULL) { s_container = 0; return 0; }
    return s_container;
}

BOOL TigerList_ReadLPPosition(float out[3])
{
    if (!out) return FALSE;
    out[0] = out[1] = out[2] = 0.0f;

    if (Skeleton_GetCachedLPRootPos(out)) {
        return TRUE;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    if (!s_ready) TigerList_Init();
    if (!s_ready) return FALSE;

    UINT64 container = TigerList_GetContainer();
    if (!container) return FALSE;

    UINT64 arrPtr = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, container + 0x08, &arrPtr, 8);
    BYOVD_UNLOCK();
    if (arrPtr < 0x10000ULL) return FALSE;

    int lpIdx = LP_GetLocalPlayerIndex();
    if (lpIdx < 0 || lpIdx >= TL_MAX_SLOTS) return FALSE;

    UINT64 slotVA = arrPtr + (UINT64)lpIdx * TL_STRIDE;
    UINT32 boneHdl = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, slotVA + TL_OFF_BONE_HDL, &boneHdl, 4);
    BYOVD_UNLOCK();

    if (!boneHdl || boneHdl == 0xFFFFFFFFu) return FALSE;

    // Resolve sobject to real bone handle
    UINT32 sobj_hdl = boneHdl;
    UINT64 sobj_va = esp_datum_resolve(cr3, sobj_hdl);
    if (sobj_va < 0x10000ULL) return FALSE;
    UINT32 sobj_type = 0;
    UINT32 real_bone_hdl = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x08u, &sobj_type, 4);
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x38u, &real_bone_hdl, 4);
    BYOVD_UNLOCK();
    if (sobj_type != 12) return FALSE;
    if (!real_bone_hdl || real_bone_hdl == 0xFFFFFFFFu) return FALSE;
    boneHdl = real_bone_hdl;

    UINT64 boneComp = 0;

    if (lpIdx == s_lpCachedSlotIdx && boneHdl == s_lpCachedBoneHdl && s_lpCachedBoneComp >= 0x10000ULL) {
        if (_validate_skeleton_comp(cr3, s_lpCachedBoneComp, NULL)) {
            boneComp = s_lpCachedBoneComp;
        }
    }

    if (!boneComp) {
        UINT64 direct = esp_datum_resolve(cr3, boneHdl);
        if (direct && _validate_skeleton_comp(cr3, direct, NULL)) {
            boneComp = direct;
        }

        if (!boneComp && g_EspState.datum_valid) {
            UINT32 _salt = boneHdl >> 13;
            UINT64 _idx  = (UINT64)(_salt & ((_salt | 0x0FFC0000u) >> 18u));
            if (_idx <= 0x15000ULL) {
                UINT64 _tbl = g_EspState.datum_table_va + _idx * 64ULL;
                UINT64 _db  = 0; UINT32 _st = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA_NoCache(cr3, _tbl + 0x08, &_db, 8);
                BYOVD_ReadVA_NoCache(cr3, _tbl + 0x30, &_st, 4);
                BYOVD_UNLOCK();
                if (_db > 0x10000ULL && _st > 0) {
                    UINT32 _startIdx = boneHdl & 0x1FFFu;
                    int _zeros = 0;
                    UINT32 _i;
                    for (_i = 0; _i < 64 && !boneComp; _i++) {
                        UINT64 _ent = _db + (UINT64)_st * (UINT64)((_startIdx + _i) & 0x1FFFu);
                        BYTE _hdr[0x18];
                        BOOL _ok;
                        UINT32 _et;
                        INT32 _h2;
                        UINT64 _comp;

                        BYOVD_LOCK();
                        _ok = BYOVD_ReadVA(cr3, _ent, _hdr, sizeof(_hdr));
                        BYOVD_UNLOCK();
                        if (!_ok) break;

                        memcpy(&_et, _hdr, 4);
                        if ((_et & 0xFFFF0000u) == 0xFEEF0000u) continue;
                        if (!_et) { if (++_zeros > 8) break; continue; }
                        _zeros = 0;

                        memcpy(&_h2, _hdr + 0x14, 4);
                        if (_h2 <= 0) continue;

                        _comp = esp_datum_resolve(cr3, (UINT32)_h2);
                        if (_comp && _validate_skeleton_comp(cr3, _comp, NULL)) {
                            boneComp = _comp;
                        }
                    }
                }
            }
        }
    }

    if (boneComp >= 0x10000ULL) {
        s_lpCachedSlotIdx  = lpIdx;
        s_lpCachedBoneHdl  = boneHdl;
        s_lpCachedBoneComp = boneComp;
    }

    if (boneComp >= 0x10000ULL) {
        float rpos[3] = {0};
        BYOVD_LOCK();
        BOOL ok = BYOVD_ReadVA_NoCache(cr3, boneComp + TL_BONE_ROOT_POS_OFF, rpos, 12);
        BYOVD_UNLOCK();

        if (ok && (rpos[0] != 0.0f || rpos[1] != 0.0f || rpos[2] != 0.0f) &&
            fabsf(rpos[0]) < 500000.0f && fabsf(rpos[1]) < 500000.0f && fabsf(rpos[2]) < 500000.0f) {
            out[0] = rpos[0]; out[1] = rpos[1]; out[2] = rpos[2];
            return TRUE;
        }
    }

    return FALSE;
}

BOOL TigerList_ReadLPHeadPosition(float out[3])
{
    if (!out) return FALSE;
    out[0] = out[1] = out[2] = 0.0f;

    if (Skeleton_GetCachedLPHeadPos(out)) {
        return TRUE;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    if (!s_ready) TigerList_Init();
    if (!s_ready) return FALSE;

    UINT64 container = TigerList_GetContainer();
    if (!container) return FALSE;

    UINT64 arrPtr = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, container + 0x08, &arrPtr, 8);
    BYOVD_UNLOCK();
    if (arrPtr < 0x10000ULL) return FALSE;

    INT32 lpIdx = LP_GetLocalPlayerIndex();
    if (lpIdx < 0 || lpIdx >= TL_MAX_SLOTS) return FALSE;

    UINT64 entVA = arrPtr + (UINT64)lpIdx * TL_STRIDE;
    UINT32 boneHdl = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, entVA + TL_OFF_BONE_HDL, &boneHdl, 4);
    BYOVD_UNLOCK();
    if (!boneHdl || boneHdl == 0xFFFFFFFFu) return FALSE;

    // Resolve sobject to real bone handle
    UINT32 sobj_hdl = boneHdl;
    UINT64 sobj_va = esp_datum_resolve(cr3, sobj_hdl);
    if (sobj_va < 0x10000ULL) return FALSE;
    UINT32 sobj_type = 0;
    UINT32 real_bone_hdl = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x08u, &sobj_type, 4);
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x38u, &real_bone_hdl, 4);
    BYOVD_UNLOCK();
    if (sobj_type != 12) return FALSE;
    if (!real_bone_hdl || real_bone_hdl == 0xFFFFFFFFu) return FALSE;
    boneHdl = real_bone_hdl;

    UINT64 boneComp = 0;

    if (lpIdx == s_lpCachedSlotIdx && boneHdl == s_lpCachedBoneHdl && s_lpCachedBoneComp >= 0x10000ULL) {
        boneComp = s_lpCachedBoneComp;
    } else {
        UINT64 direct = esp_datum_resolve(cr3, boneHdl);
        if (direct && _validate_skeleton_comp(cr3, direct, NULL)) {
            boneComp = direct;
        } else {
            UINT32 _salt = boneHdl >> 13;
            UINT64 _idx  = (UINT64)(_salt & ((_salt | 0x0FFC0000u) >> 18u));
            if (_idx <= 0x15000ULL) {
                UINT64 _tbl = g_EspState.datum_table_va + _idx * 64ULL;
                UINT64 _db  = 0; UINT32 _st = 0;
                BYOVD_LOCK();
                BYOVD_ReadVA_NoCache(cr3, _tbl + 0x08, &_db, 8);
                BYOVD_ReadVA_NoCache(cr3, _tbl + 0x30, &_st, 4);
                BYOVD_UNLOCK();
                if (_db > 0x10000ULL && _st > 0) {
                    UINT32 _startIdx = boneHdl & 0x1FFFu;
                    int _zeros = 0;
                    UINT32 _i;
                    for (_i = 0; _i < 64 && !boneComp; _i++) {
                        UINT64 _ent = _db + (UINT64)_st * (UINT64)((_startIdx + _i) & 0x1FFFu);
                        BYTE _hdr[0x18];
                        BOOL _ok;
                        UINT32 _et;
                        INT32 _h2;
                        UINT64 _comp;

                        BYOVD_LOCK();
                        _ok = BYOVD_ReadVA(cr3, _ent, _hdr, sizeof(_hdr));
                        BYOVD_UNLOCK();
                        if (!_ok) break;

                        memcpy(&_et, _hdr, 4);
                        if ((_et & 0xFFFF0000u) == 0xFEEF0000u) continue;
                        if (!_et) { if (++_zeros > 8) break; continue; }
                        _zeros = 0;

                        memcpy(&_h2, _hdr + 0x14, 4);
                        if (_h2 <= 0) continue;

                        _comp = esp_datum_resolve(cr3, (UINT32)_h2);
                        if (_comp && _validate_skeleton_comp(cr3, _comp, NULL)) {
                            boneComp = _comp;
                        }
                    }
                }
            }
        }
    }

    if (boneComp >= 0x10000ULL) {
        s_lpCachedSlotIdx  = lpIdx;
        s_lpCachedBoneHdl  = boneHdl;
        s_lpCachedBoneComp = boneComp;
    }

    if (!boneComp || boneComp < 0x10000ULL) {
        return FALSE;
    }

    BYTE slabBuf[0x3E0];
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, boneComp, slabBuf, sizeof(slabBuf));
    BYOVD_UNLOCK();
    if (!ok) return FALSE;

    INT32 count = 0;
    memcpy(&count, slabBuf + TL_BONE_DESC_CNT_OFF, 4);
    if (count <= 18) return FALSE;

    float rootQuat[4];
    float rootPos[3];
    memcpy(rootQuat, slabBuf + TL_BONE_ROOT_QUAT_OFF, 16);
    memcpy(rootPos,  slabBuf + TL_BONE_ROOT_POS_OFF,  12);

    for (int i = 0; i < 4; i++) if (!_finite_f(rootQuat[i])) return FALSE;
    for (int i = 0; i < 3; i++) if (!_finite_f(rootPos[i])) return FALSE;

    BYTE *be = slabBuf + TL_BONE_DESC_DATA_OFF + 18 * TL_BONE_STRIDE;
    float v[3];
    v[0] = *(float*)(be + TL_BONE_POS_OFF);
    v[1] = *(float*)(be + TL_BONE_POS_OFF + 4);
    v[2] = *(float*)(be + TL_BONE_POS_OFF + 8);

    if (!_vec_ok(v[0], v[1], v[2])) return FALSE;

    float rotated[3];
    quat_rotate(rootQuat, v, rotated);

    out[0] = rotated[0] + rootPos[0];
    out[1] = rotated[1] + rootPos[1];
    out[2] = rotated[2] + rootPos[2];

    return TRUE;
}

static BOOL _validate_skeleton_comp(UINT64 cr3, UINT64 comp, INT32 *cnt_out)
{
    if (comp < 0x10000ULL) return FALSE;

    BYTE slab[0x180];
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, comp, slab, sizeof(slab));
    BYOVD_UNLOCK();
    if (!ok) return FALSE;

    INT32 count = 0;
    memcpy(&count, slab + TL_BONE_DESC_CNT_OFF, 4);
    if (count < 10 || count > 128) return FALSE;

    float rootQuat[4];
    float rootPos[4];
    memcpy(rootQuat, slab + TL_BONE_ROOT_QUAT_OFF, 16);
    memcpy(rootPos,  slab + TL_BONE_ROOT_POS_OFF,  16);

    int i;
    for (i = 0; i < 4; i++) {
        if (!_finite_f(rootQuat[i]) || !_finite_f(rootPos[i])) return FALSE;
    }

    if (rootPos[0] == 0.0f && rootPos[1] == 0.0f && rootPos[2] == 0.0f) return FALSE;

    if (cnt_out) *cnt_out = count;
    return TRUE;
}

int TigerList_ReadBones(int slotIndex, UINT64 cr3, UINT64 arrPtr,
                        const float entityWorldPos[3],
                        TlVec3 *outBones, short *outParents, int maxBones,
                        float rootPosOut[3])
{
    if (slotIndex < 0 || slotIndex >= TL_MAX_SLOTS) return 0;
    if (!outBones || maxBones <= 0 || !entityWorldPos) return 0;
    if (!cr3 || !g_EspState.datum_valid) return 0;

    if (!arrPtr) {
        UINT64 container = TigerList_GetContainer();
        if (!container) return 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, container + 0x08, &arrPtr, 8);
        BYOVD_UNLOCK();
        if (arrPtr < 0x10000ULL) return 0;
    }

    UINT64 entVA = arrPtr + (UINT64)slotIndex * TL_STRIDE;
    UINT32 hdl   = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, entVA + TL_OFF_BONE_HDL, &hdl, 4);
    BYOVD_UNLOCK();
    if (!hdl || hdl == 0xFFFFFFFFu) return 0;

    // Resolve sobject to real bone handle
    UINT32 sobj_hdl = hdl;
    UINT64 sobj_va = esp_datum_resolve(cr3, sobj_hdl);
    if (sobj_va < 0x10000ULL) return 0;
    UINT32 sobj_type = 0;
    UINT32 real_bone_hdl = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x08u, &sobj_type, 4);
    BYOVD_ReadVA_NoCache(cr3, sobj_va + 0x38u, &real_bone_hdl, 4);
    BYOVD_UNLOCK();
    if (sobj_type != 12) return 0;
    if (!real_bone_hdl || real_bone_hdl == 0xFFFFFFFFu) return 0;
    hdl = real_bone_hdl;

    INT32  boneCount   = 0;
    UINT64 boneComp    = 0;

    UINT64 direct = esp_datum_resolve(cr3, hdl);
    if (direct && _validate_skeleton_comp(cr3, direct, &boneCount)) {
        boneComp = direct;
    }

    if (!boneComp) {
        UINT32 _salt = hdl >> 13;
        UINT64 _idx  = (UINT64)(_salt & ((_salt | 0x0FFC0000u) >> 18u));
        if (_idx <= 0x15000ULL) {
            UINT64 _tbl = g_EspState.datum_table_va + _idx * 64ULL;
            UINT64 _db  = 0; UINT32 _st = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, _tbl + 0x08, &_db, 8);
            BYOVD_ReadVA_NoCache(cr3, _tbl + 0x30, &_st, 4);
            BYOVD_UNLOCK();
            if (_db > 0x10000ULL && _st > 0) {
                UINT32 _startIdx = hdl & 0x1FFFu;
                int _zeros = 0;
                UINT32 _i;
                for (_i = 0; _i < 64 && !boneComp; _i++) {
                    UINT64 _ent = _db + (UINT64)_st * (UINT64)((_startIdx + _i) & 0x1FFFu);
                    BYTE _hdr[0x18];
                    BOOL _ok;
                    UINT32 _et;
                    INT32 _h2;
                    UINT64 _comp;

                    BYOVD_LOCK();
                    _ok = BYOVD_ReadVA(cr3, _ent, _hdr, sizeof(_hdr));
                    BYOVD_UNLOCK();
                    if (!_ok) break;

                    memcpy(&_et, _hdr, 4);
                    if ((_et & 0xFFFF0000u) == 0xFEEF0000u) continue;
                    if (!_et) { if (++_zeros > 8) break; continue; }
                    _zeros = 0;

                    memcpy(&_h2, _hdr + 0x14, 4);
                    if (_h2 <= 0) continue;

                    _comp = esp_datum_resolve(cr3, (UINT32)_h2);
                    if (_comp && _validate_skeleton_comp(cr3, _comp, &boneCount)) {
                        boneComp = _comp;
                    }
                }
            }
        }
    }

    if (!boneComp || boneCount <= 0 || boneCount > maxBones || boneCount > 128) return 0;

    UINT32 boneArrayOff  = TL_BONE_DESC_DATA_OFF;
    UINT32 parentArrayOff = boneArrayOff + (UINT32)boneCount * TL_BONE_STRIDE;
    UINT32 parentArraySz  = (UINT32)boneCount * sizeof(short);
    UINT32 slabSize       = parentArrayOff + parentArraySz;

    if (slabSize > 5000u) return 0;

    BYTE slabBuf[5000];
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, boneComp, slabBuf, slabSize);
    BYOVD_UNLOCK();
    if (!ok) {
        _tl_log_fmt("ReadBones Slot %d: Failed to read slabBuf (size %u) at 0x%I64X", slotIndex, slabSize, boneComp);
        return 0;
    }

    static BOOL s_slot_hexdumped[TL_MAX_SLOTS] = { FALSE };
    if (!s_slot_hexdumped[slotIndex]) {
        char label[128];
        wsprintfA(label, "Slot[%d] BoneComp Slab Header (0x80 bytes)", slotIndex);
        _tl_hexdump(label, boneComp, slabBuf, slabSize < 0x80 ? slabSize : 0x80);
        s_slot_hexdumped[slotIndex] = TRUE;
    }

    float rootQuat[4];
    float rootPos[3];
    memcpy(rootQuat, slabBuf + TL_BONE_ROOT_QUAT_OFF, 16);
    memcpy(rootPos,  slabBuf + TL_BONE_ROOT_POS_OFF,  12);

    for (int i = 0; i < 4; i++) if (!_finite_f(rootQuat[i])) return 0;
    for (int i = 0; i < 3; i++) if (!_finite_f(rootPos[i])) return 0;

    short *parentArr = (short*)(slabBuf + parentArrayOff);

    for (INT32 bi = 0; bi < boneCount; bi++) {
        BYTE *be = slabBuf + boneArrayOff + (UINT64)bi * TL_BONE_STRIDE;
        float v[3];
        v[0] = *(float*)(be + TL_BONE_POS_OFF);
        v[1] = *(float*)(be + TL_BONE_POS_OFF + 4);
        v[2] = *(float*)(be + TL_BONE_POS_OFF + 8);

        if (!_vec_ok(v[0], v[1], v[2])) {
            outBones[bi].x = outBones[bi].y = outBones[bi].z = 0.0f;
            if (outParents) outParents[bi] = -1;
            continue;
        }
        if (outParents) {
            outParents[bi] = parentArr[bi];
        }
        float rotated[3];
        quat_rotate(rootQuat, v, rotated);
        outBones[bi].x = rotated[0] + rootPos[0];
        outBones[bi].y = rotated[1] + rootPos[1];
        outBones[bi].z = rotated[2] + rootPos[2];
    }
    if (rootPosOut) {
        rootPosOut[0] = rootPos[0];
        rootPosOut[1] = rootPos[1];
        rootPosOut[2] = rootPos[2];
    }
    return boneCount;
}

}

#pragma optimize("", on)
