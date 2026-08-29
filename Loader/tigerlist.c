/* tigerlist.c — PObjects (TigerList) slot array reader and bone resolver */
#include "esp.h"
#include "tigerlist.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "local_player.h"
#include "skeleton.h"
#include <string.h>
#include <math.h>
#include "syscalls.h"


/* Disable compiler optimization for the entire translation unit.
 * Release build (/O2) optimizations aggressively reorder and cache
 * TigerList PObject container decryption and bone transformation state. */
#pragma optimize("", off)


#ifndef NDEBUG
static void _tl_log(const char *msg) {
    char buf[640];
    wsprintfA(buf, "[TL][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    OutputDebugStringA(buf);
}
#define TL_LOG(msg) _tl_log(msg)
#else
#define TL_LOG(msg) ((void)0)
#endif



/* Module state */
static UINT64 s_encVA     = 0;
static UINT64 s_container = 0;
static BOOL   s_ready     = FALSE;

/* Local Player Bone Component Cache (Stealth Performance Optimization) */
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

#include "xor_strings.h"

BOOL TigerList_Init(void)
{
    if (s_ready) return TRUE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return FALSE;

    /* Reuse VA from esp.h compat state if already resolved */
    if (g_EspState.tl_valid && g_EspState.g_players_va) {
        s_encVA = g_EspState.g_players_va;
        s_ready = TRUE;
        return TRUE;
    }

    s_encVA = d2Base + SecureReadStatic(&OBF_OFF_TigerListBase);
    s_ready = (s_encVA >= 0x10000ULL);

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

    /* Dyn sync s_encVA with g_EspState.g_players_va if it gets resolved elsewhere */
    if (g_EspState.tl_valid && g_EspState.g_players_va && g_EspState.g_players_va != s_encVA) {
        s_encVA = g_EspState.g_players_va;
    }

    static DWORD s_lastTick = 0;
    DWORD now = GetTickCount();
    /* 500ms cache: container VA is stable for the entire game session.
     * Old 16ms cache almost never hit on a 20ms heavy-tick, forcing a
     * full ESP_DecryptPtr (30+ iteration state machine) every tick. */
    if (s_container >= 0x10000ULL && (now - s_lastTick < 500))
        return s_container;

    s_container = ESP_DecryptPtr(cr3, s_encVA);
    s_lastTick  = now;
    if (s_container < 0x10000ULL) { s_container = 0; return 0; }
    return s_container;
}


BOOL TigerList_ReadLPPosition(float out[3])
{
    if (!out) return FALSE;
    out[0] = out[1] = out[2] = 0.0f;

    UINT64 lpBody = TigerList_GetLPHavokRigidBody();
    if (lpBody < 0x10000ULL) return FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    float pos[3] = {0};
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, lpBody + 0x1C0u, pos, 12);
    BYOVD_UNLOCK();

    if (ok && (pos[0] != 0.0f || pos[1] != 0.0f || pos[2] != 0.0f) &&
        fabsf(pos[0]) < 500000.0f && fabsf(pos[1]) < 500000.0f && fabsf(pos[2]) < 500000.0f) {
        out[0] = pos[0]; out[1] = pos[1]; out[2] = pos[2];
        return TRUE;
    }
    return FALSE;
}

BOOL TigerList_ReadLPHeadPosition(float out[3])
{
    BOOL ok = TigerList_ReadLPPosition(out);
    if (ok) {
        out[2] += 0.8f;
    }
    return ok;
}

UINT64 TigerList_GetLPHavokRigidBody(void)
{
    extern UINT64 Fly_GetLpEp(void);
    return Fly_GetLpEp();
}

static BOOL _validate_skeleton_comp(UINT64 cr3, UINT64 comp, INT32 *cnt_out)
{
    if (comp < 0x10000ULL) return FALSE;

    /* Read header (0x180 bytes cover count, rootQuat, and rootPos) */
    BYTE slab[0x180];
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, comp, slab, sizeof(slab));
    BYOVD_UNLOCK();
    if (!ok) return FALSE;

    INT32 count = 0;
    memcpy(&count, slab + TL_BONE_DESC_CNT_OFF, 4); // 0x140
    if (count < 10 || count > 128) return FALSE;

    float rootQuat[4];
    float rootPos[4];
    memcpy(rootQuat, slab + TL_BONE_ROOT_QUAT_OFF, 16); // 0xB0
    memcpy(rootPos,  slab + TL_BONE_ROOT_POS_OFF,  16); // 0xC0

    /* Check finite */
    int i;
    for (i = 0; i < 4; i++) {
        if (!_finite_f(rootQuat[i]) || !_finite_f(rootPos[i])) return FALSE;
    }

    /* Reject zeroed-out (inactive) skeletons — position must not be all zeros */
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

    /* If caller already resolved arrPtr, use it directly (no BYOVD needed).
     * Fall back to internal resolution only when arrPtr == 0. */
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

    INT32  boneCount   = 0;
    UINT64 boneComp    = 0;

    /* 1. Try direct resolve with validation */
    UINT64 direct = esp_datum_resolve(cr3, hdl);
    if (direct && _validate_skeleton_comp(cr3, direct, &boneCount)) {
        boneComp = direct;
    }

    /* 2. Chain walk — identical to find_skeleton and Rust walk_linear_chain. */
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
                for (_i = 0; _i < 8 && !boneComp; _i++) {
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

#ifndef NDEBUG
    {
        char _dbl[128];
        wsprintfA(_dbl, "[TL_BONE] slot=%d hdl=0x%08X boneComp=0x%I64X cnt=%d datum_valid=%d",
                  slotIndex, hdl, boneComp, boneCount, g_EspState.datum_valid);
        TL_LOG(_dbl);
    }
#endif

    if (!boneComp || boneCount <= 0 || boneCount > maxBones || boneCount > 128) return 0;

    /* Layout of boneComp:
     *   +0x000..+0x17F  header (rootQuat @ 0xB0, rootPos @ 0xC0, count @ 0x140)
     *   +0x180..        bone transforms: boneCount * 0x20 (quat+pos+4pad each)
     *   +0x180+cnt*0x20 parent index array: boneCount * sizeof(int16_t)
     *
     * We read everything in one shot: header + transforms + parent array.
     * parentBuf sits immediately after the last bone transform. */
    UINT32 boneArrayOff  = TL_BONE_DESC_DATA_OFF;                          /* 0x180 */
    UINT32 parentArrayOff = boneArrayOff + (UINT32)boneCount * TL_BONE_STRIDE;
    UINT32 parentArraySz  = (UINT32)boneCount * sizeof(short);             /* int16_t per bone */
    UINT32 slabSize       = parentArrayOff + parentArraySz;

    /* Safety cap: 0x180 + 128*0x20 + 128*2 = 4736 bytes */
    if (slabSize > 5000u) return 0;

    BYTE slabBuf[5000];

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, boneComp, slabBuf, slabSize);
    BYOVD_UNLOCK();
    if (!ok) return 0;

    /* Extract root rotation and position global vectors from the slab buffer */
    float rootQuat[4];
    float rootPos[3];
    memcpy(rootQuat, slabBuf + TL_BONE_ROOT_QUAT_OFF, 16);
    memcpy(rootPos,  slabBuf + TL_BONE_ROOT_POS_OFF,  12);

    /* Validate float values inside the extracted data to filter corrupted memory */
    for (int i = 0; i < 4; i++) if (!_finite_f(rootQuat[i])) return 0;
    for (int i = 0; i < 3; i++) if (!_finite_f(rootPos[i])) return 0;

    /* Parent index array starts right after the bone transform array.
     * Each entry is int16_t: -1 means root (no parent), 0..N-1 = parent bone index. */
    short *parentArr = (short*)(slabBuf + parentArrayOff);

#ifndef NDEBUG
    {
        /* Log first 8 parent indices from both sources to verify layout */
        char _pdbg[256];
        int _lim = boneCount < 8 ? boneCount : 8;
        char _p1[64] = "", _p2[64] = "";
        for (int _pi = 0; _pi < _lim; _pi++) {
            BYTE *_be = slabBuf + boneArrayOff + (UINT64)_pi * TL_BONE_STRIDE;
            short _from1c = *(short*)(_be + 0x1C);
            short _fromArr = parentArr[_pi];
            char _tmp[16];
            wsprintfA(_tmp, "%d,", (int)_from1c); lstrlenA(_p1)+lstrlenA(_tmp)<60 ? (lstrcatA(_p1,_tmp),0) : 0;
            wsprintfA(_tmp, "%d,", (int)_fromArr); lstrlenA(_p2)+lstrlenA(_tmp)<60 ? (lstrcatA(_p2,_tmp),0) : 0;
        }
        wsprintfA(_pdbg, "[PARENT] slot=%d cnt=%d +0x1C=[%s] arr=[%s]",
                  slotIndex, boneCount, _p1, _p2);
        TL_LOG(_pdbg);
    }
#endif

    /* Parse bones local coordinates and transform them to world space */
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
            /* Use parent array (after bone transforms) — this is the real hierarchy */
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

#pragma optimize("", on)
