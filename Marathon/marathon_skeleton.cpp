/* marathon_skeleton.cpp — Marathon TigerList skeleton reader with thread-safe snapshot for the overlay */
#include "skeleton.h"
#include "marathon_tigerlist.h"
#include "esp.h"
#include "esp_overlay.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lists.h"
#include "local_player.h"
#include <string.h>
#include <stdio.h>

extern "C" void EspOverlay_PushBoxSnapshot(const EspBox *boxes, int n);

#pragma optimize("", off)

#include "debug.h"

static void _write_sk_diag(const char* msg) {
    WriteLogFileEx("seraph_debug.log", msg);
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH - 64);
    if (!n || n >= MAX_PATH - 64) return;
    lstrcatA(path, "\\Downloads\\skeleton.log");
    HANDLE hF = CreateFileA(path, FILE_APPEND_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, msg, (DWORD)lstrlenA(msg), &w, NULL);
        CloseHandle(hF);
    }
}

static void _sk_log(const char *msg) {
    char buf[512];
    wsprintfA(buf, "[SKELETON][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    _write_sk_diag(buf);
}
#define SK_LOG(msg) _sk_log(msg)

static void _sk_log_fmt(const char *fmt, ...) {
    char msg[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg) - 1, fmt, args);
    va_end(args);
    _sk_log(msg);
}

static void _sk_hexdump(const char* label, UINT64 va, const void* data, size_t size) {
    if (!data || size == 0) return;
    _sk_log_fmt("--- HEX DUMP: %s (VA: 0x%I64X, Size: %zu) ---", label, va, size);
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
        _write_sk_diag(line);
    }
    _sk_log("--- END HEX DUMP ---");
}

extern "C" UINT64 get_cached_xor_key(UINT32 rva, UINT64 image_base);

static volatile LONG s_snapLock   = 0;
static SkelEntity    s_snap[SKEL_ENTITY_MAX];
static int           s_snapFilled = 0;
static float         s_snapView[16];
static float         s_snapProj[16];
static BOOL          s_snapMatValid = FALSE;
static DWORD         s_lastSnapTick = 0;
static DWORD         s_lastMatTick  = 0;

static void _snap_lock(void)   { while (InterlockedCompareExchange(&s_snapLock, 1, 0)) { YieldProcessor(); } }
static void _snap_unlock(void) { InterlockedExchange(&s_snapLock, 0); }

extern "C" {

int Skeleton_GetCached(SkelEntity *out, int max)
{
    if (!out || max <= 0) return 0;
    _snap_lock();
    int n = s_snapFilled < max ? s_snapFilled : max;
    if (n > 0) memcpy(out, s_snap, (size_t)n * sizeof(SkelEntity));
    _snap_unlock();
    return n;
}

BOOL Skeleton_GetCachedMatrices(float view[16], float proj[16])
{
    _snap_lock();
    BOOL ok = s_snapMatValid;
    if (ok) { memcpy(view, s_snapView, 64); memcpy(proj, s_snapProj, 64); }
    _snap_unlock();
    return ok;
}

static volatile LONG s_threadStarted  = 0;
static volatile LONG s_threadStop     = 0;
static HANDLE        s_skelThread     = NULL;

static volatile LONG s_boxThreadStarted = 0;
static HANDLE        s_boxThread        = NULL;

static DWORD WINAPI _BoxUpdateThread(LPVOID p)
{
    (void)p;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    while (InterlockedCompareExchange(&s_threadStop, 0, 0) == 0) {
        if (GetDestiny2CR3()) {
            DWORD t0 = GetTickCount();
            EspBox boxes[ESP_MAX_BOXES];
            int bn = ESP_GetEntityBoxes(sw, sh, boxes, ESP_MAX_BOXES);
            EspOverlay_PushBoxSnapshot(boxes, bn);
            DWORD elapsed = GetTickCount() - t0;
            if (elapsed < 16u) Sleep(16u - elapsed);
        } else {
            Sleep(33);
        }
    }
    InterlockedExchange(&s_boxThreadStarted, 0);
    return 0;
}

static DWORD WINAPI _SkelUpdateThread(LPVOID p)
{
    (void)p;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    SK_LOG("Skeleton update thread started.");

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    while (InterlockedCompareExchange(&s_threadStop, 0, 0) == 0) {
        if (!GetDestiny2CR3()) { Sleep(50); continue; }

        DWORD t0 = GetTickCount();

        SkelEntity tmp[SKEL_ENTITY_MAX];
        int count = Skeleton_ReadAll(tmp, SKEL_ENTITY_MAX);

        float v[16], pr[16];
        BOOL matOk = ESP_ReadMatrices(v, pr);
        if (!matOk) matOk = ESP_GetCachedMatrices(v, pr);

        _snap_lock();
        DWORD nowTick = GetTickCount();
        if (count > 0) {
            s_snapFilled = count;
            memcpy(s_snap, tmp, (size_t)count * sizeof(SkelEntity));
            s_lastSnapTick = nowTick;
        } else if (nowTick - s_lastSnapTick > 1000) {
            s_snapFilled = 0;
        }

        if (matOk) {
            memcpy(s_snapView, v, 64);
            memcpy(s_snapProj, pr, 64);
            s_snapMatValid = TRUE;
            s_lastMatTick = nowTick;
        } else if (nowTick - s_lastMatTick > 1000) {
            s_snapMatValid = FALSE;
        }
        _snap_unlock();

        DWORD elapsed = GetTickCount() - t0;
        if (elapsed < 7u) Sleep(7u - elapsed);
    }

    SK_LOG("Skeleton update thread exiting.");
    InterlockedExchange(&s_threadStarted, 0);
    InterlockedExchange(&s_threadStop,    0);
    return 0;
}

void Skeleton_StartUpdateThread(void)
{
    if (InterlockedCompareExchange(&s_threadStarted, 1, 0) != 0) return;
    InterlockedExchange(&s_threadStop, 0);
    HANDLE h = CreateThread(NULL, 0, _SkelUpdateThread, NULL, 0, NULL);
    if (!h) { InterlockedExchange(&s_threadStarted, 0); return; }
    s_skelThread = h;
    if (InterlockedCompareExchange(&s_boxThreadStarted, 1, 0) == 0) {
        HANDLE hb = CreateThread(NULL, 0, _BoxUpdateThread, NULL, 0, NULL);
        if (hb) s_boxThread = hb;
        else InterlockedExchange(&s_boxThreadStarted, 0);
    }
}

void Skeleton_StopUpdateThread(void)
{
    InterlockedExchange(&s_threadStop, 1);
    if (s_skelThread) {
        WaitForSingleObject(s_skelThread, 2000);
        CloseHandle(s_skelThread);
        s_skelThread = NULL;
    }
    if (s_boxThread) {
        WaitForSingleObject(s_boxThread, 2000);
        CloseHandle(s_boxThread);
        s_boxThread = NULL;
    }
    InterlockedExchange(&s_threadStarted, 0);
    InterlockedExchange(&s_boxThreadStarted, 0);
    _snap_lock();
    s_snapFilled   = 0;
    s_snapMatValid = FALSE;
    _snap_unlock();
}

static BOOL _sl_lookup(const BYTE *slBuf, UINT64 slBase,
                       UINT64 resolvedPtr, float wpos[3], INT32 *teamOut)
{
    for (int ei = 0; ei < 32; ei++) {
        UINT64 entry = slBase + (UINT64)ei * 0x200u;
        if (resolvedPtr < entry || resolvedPtr >= entry + 0x200u) continue;
        const BYTE *s   = slBuf + (UINT64)ei * 0x200u;
        UINT16 team16   = *(UINT16*)(s + 0x0C0u);
        if (team16 == 0xFF00u) return FALSE;
        float ex = *(float*)(s + 0x1A0u);
        float ey = *(float*)(s + 0x1A4u);
        float ez = *(float*)(s + 0x1A8u);
        if (!_vec_ok(ex, ey, ez)) return FALSE;
        wpos[0] = ex; wpos[1] = ey; wpos[2] = ez;
        *teamOut = (team16 <= 10) ? (INT32)team16 : -1;
        return TRUE;
    }
    return FALSE;
}

typedef struct { UINT32 key; char name[64]; } NameCacheEntry;
static NameCacheEntry s_nameCache[TL_MAX_SLOTS];

typedef struct {
    TlVec3 bones[SKEL_BONE_MAX];
    short  boneParents[SKEL_BONE_MAX];
    int    boneCount;
    float  rootPos[3];
    DWORD  lastValidTick;
} SlotBoneCache;
static SlotBoneCache s_boneCache[TL_MAX_SLOTS];

int Skeleton_ReadAll(SkelEntity *out, int max)
{
    if (!out || max <= 0) return 0;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return 0;

    if (!TigerList_IsReady()) TigerList_Init();

    UINT64 container = TigerList_GetContainer();
    if (!container) return 0;

    UINT64 tlArrPtr = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, container + 0x08, &tlArrPtr, 8);
    BYOVD_UNLOCK();
    if (tlArrPtr < 0x10000ULL) return 0;

    typedef struct {
        UINT32 team;
        UINT32 boneHdl;
        UINT32 playerDefHdl;
        UINT32 hpHdl;
        UINT32 lpMark;
        BYTE   nameCipher[64];
    } SlotHdr;
    SlotHdr headers[TL_MAX_SLOTS];
    memset(headers, 0, sizeof(headers));

    typedef struct {
        BYTE range1[0x88]; /* 0x0004 .. 0x0088 (reads playerDefHdl at 0x04 and sobject_handle at 0x84) */
        BYTE range2[4];    /* 0x0120u .. 0x0124 (team) */
        BYTE range3[4];    /* 0x74C8u .. 0x74CC (health_handle) */
    } SlotBuffers;
    static SlotBuffers slotBufs[TL_MAX_SLOTS];
    memset(slotBufs, 0, sizeof(slotBufs));

    BYOVD_READ_BATCH_ENTRY batch[TL_MAX_SLOTS * 3];
    int bc = 0;
    for (int ti = 0; ti < TL_MAX_SLOTS; ti++) {
        UINT64 sv = tlArrPtr + (UINT64)ti * TL_STRIDE;
        batch[bc].va = sv + 0x0004u; batch[bc].buf = slotBufs[ti].range1; batch[bc].size = 0x84; bc++;
        batch[bc].va = sv + 0x0120u; batch[bc].buf = slotBufs[ti].range2; batch[bc].size = 4;    bc++;
        batch[bc].va = sv + 0x74C8u; batch[bc].buf = slotBufs[ti].range3; batch[bc].size = 4;    bc++;
    }
    BYOVD_ReadBatch(cr3, batch, bc);

    for (int ti = 0; ti < TL_MAX_SLOTS; ti++) {
        headers[ti].playerDefHdl = *(UINT32*)(slotBufs[ti].range1 + 0);
        headers[ti].lpMark       = 0; 
        
        wsprintfA((char*)headers[ti].nameCipher, "Player_%d", ti);
        
        headers[ti].team         = *(UINT32*)(slotBufs[ti].range2);
        headers[ti].boneHdl      = *(UINT32*)(slotBufs[ti].range1 + 0x80); // 0x0084 - 0x0004 = 0x80 (sobject_handle)
        headers[ti].hpHdl        = *(UINT32*)(slotBufs[ti].range3);
    }

    static BOOL s_slot0_dumped = FALSE;
    if (!s_slot0_dumped && tlArrPtr >= 0x10000ULL) {
        _sk_hexdump("Slot 0 Raw Range1 (0x84 bytes)", tlArrPtr + 0x0004u, slotBufs[0].range1, 0x84);
        s_slot0_dumped = TRUE;
    }

    UINT64 slBase = ESP_GetSLListBase();
    static BYTE slBuf[32 * 0x200u];
    BOOL slOk = FALSE;
    if (slBase > 0x10000ULL) {
        BYOVD_LOCK();
        slOk = BYOVD_ReadVA(cr3, slBase, slBuf, sizeof(slBuf));
        BYOVD_UNLOCK();
    }

    UINT32 lpTeam = 0;
    INT32  lpIdx  = LP_GetLocalPlayerIndex();
    if (lpIdx >= 0 && lpIdx < TL_MAX_SLOTS) {
        lpTeam = headers[lpIdx].team;
    }

    DWORD nowTick = GetTickCount();
    int filled = 0;
    for (int ti = 0; ti < TL_MAX_SLOTS && filled < max; ti++) {
        BOOL   isLP    = (lpIdx == ti);

        if (!isLP && !is_tiger_handle(headers[ti].boneHdl)) {
            s_boneCache[ti].boneCount = 0;
            continue;
        }

        float  wpos[3] = {0,0,0};
        INT32  team    = (headers[ti].team == lpTeam || isLP) ? 0 : 1;
        BOOL   posOk   = FALSE;

        if (is_tiger_handle(headers[ti].playerDefHdl) && slOk) {
            UINT64 slPtr = esp_datum_resolve(cr3, headers[ti].playerDefHdl);
            INT32 dummySlTeam = -1;
            if (slPtr >= 0x10000ULL)
                posOk = _sl_lookup(slBuf, slBase, slPtr, wpos, &dummySlTeam);
        }

        TlVec3 bones[SKEL_BONE_MAX];
        short  parents[SKEL_BONE_MAX];
        float  rpos[3] = {0,0,0};
        int readCount = TigerList_ReadBones(ti, cr3, tlArrPtr, wpos, bones, parents, SKEL_BONE_MAX, rpos);

        static BOOL s_bone_logged[TL_MAX_SLOTS] = { FALSE };
        if (readCount > 0) {
            memcpy(s_boneCache[ti].bones, bones, (size_t)readCount * sizeof(TlVec3));
            memcpy(s_boneCache[ti].boneParents, parents, (size_t)readCount * sizeof(short));
            s_boneCache[ti].boneCount = readCount;
            s_boneCache[ti].rootPos[0] = rpos[0]; s_boneCache[ti].rootPos[1] = rpos[1]; s_boneCache[ti].rootPos[2] = rpos[2];
            s_boneCache[ti].lastValidTick = nowTick;

            if (!s_bone_logged[ti]) {
                _sk_log_fmt("Slot %d (isLP=%d, Team=%d): Skeleton READ SUCCESS (%d bones). RootPos: X=%.3f, Y=%.3f, Z=%.3f, BoneHdl=0x%08X",
                           ti, (int)isLP, team, readCount, rpos[0], rpos[1], rpos[2], headers[ti].boneHdl);
                char label[64];
                wsprintfA(label, "Slot[%d] First 4 Bones Dump", ti);
                _sk_hexdump(label, 0, bones, (size_t)(readCount < 4 ? readCount : 4) * sizeof(TlVec3));
                s_bone_logged[ti] = TRUE;
            }
        } else if (nowTick - s_boneCache[ti].lastValidTick < 250u && s_boneCache[ti].boneCount > 0) {
            readCount = s_boneCache[ti].boneCount;
            memcpy(bones, s_boneCache[ti].bones, (size_t)readCount * sizeof(TlVec3));
            memcpy(parents, s_boneCache[ti].boneParents, (size_t)readCount * sizeof(short));
            rpos[0] = s_boneCache[ti].rootPos[0]; rpos[1] = s_boneCache[ti].rootPos[1]; rpos[2] = s_boneCache[ti].rootPos[2];
        } else {
            if (s_bone_logged[ti]) {
                _sk_log_fmt("Slot %d: Skeleton lost / no longer read.", ti);
                s_bone_logged[ti] = FALSE;
            }
            s_boneCache[ti].boneCount = 0;
        }

        if (readCount > 0 && !posOk) {
            wpos[0]=bones[0].x; wpos[1]=bones[0].y; wpos[2]=bones[0].z;
            posOk=TRUE;
        }

        if (!isLP && readCount == 0) continue;
        if (!posOk && readCount == 0) continue;

        SkelEntity *e = &out[filled++];
        memset(e, 0, sizeof(*e));
        e->slotIndex     = (UINT32)ti;
        e->isLocalPlayer = isLP;
        e->team          = team;
        e->worldPos[0]   = wpos[0];
        e->worldPos[1]   = wpos[1];
        e->worldPos[2]   = wpos[2];
        e->worldPosValid = TRUE;
        if (readCount > 0) {
            e->rootPos[0] = rpos[0];
            e->rootPos[1] = rpos[1];
            e->rootPos[2] = rpos[2];
        } else {
            e->rootPos[0] = wpos[0];
            e->rootPos[1] = wpos[1];
            e->rootPos[2] = wpos[2];
        }
        e->boneCount     = (UINT32)readCount;
        if (readCount > 0) {
            memcpy(e->bones, bones, (size_t)readCount * sizeof(TlVec3));
            memcpy(e->boneParents, parents, (size_t)readCount * sizeof(short));
        }

        /* Set cached name */
        UINT32 cKey = 0;
        memcpy(&cKey, headers[ti].nameCipher, 4);
        if (s_nameCache[ti].key != cKey || s_nameCache[ti].name[0] == '\0') {
            s_nameCache[ti].key = cKey;
            memcpy(s_nameCache[ti].name, headers[ti].nameCipher, sizeof(e->name));
            memcpy(e->name, headers[ti].nameCipher, sizeof(e->name));
        } else {
            memcpy(e->name, s_nameCache[ti].name, sizeof(e->name));
        }

        e->health = 1.0f;
        e->shield = 0.0f;
        if (headers[ti].hpHdl != 0 && headers[ti].hpHdl != 0xFFFFFFFFu && g_EspState.datum_valid) {
            UINT64 hpComp = esp_datum_resolve(cr3, headers[ti].hpHdl);
            if (hpComp > 0x10000ULL) {
                UINT32 raw_hp = 0, hp_rva = 0;
                UINT32 raw_sh = 0, sh_rva = 0;
                BYOVD_LOCK();
                /* Marathon specific health component offsets: raw_hp @ 0x110, hp_rva @ 0x134 */
                BYOVD_ReadVA(cr3, hpComp + 0x110u, &raw_hp, 4);
                BYOVD_ReadVA(cr3, hpComp + 0x134u, &hp_rva, 4);
                /* Shield offsets disabled/ignored for Marathon until verified to prevent reading garbage */
                raw_sh = 0;
                sh_rva = 0;
                BYOVD_UNLOCK();

                if (hp_rva) {
                    UINT64 xor_key = get_cached_xor_key(hp_rva, GetDestiny2Base());
                    if (xor_key) {
                        UINT32 decrypted_hp = raw_hp ^ (UINT32)xor_key;
                        float hp_val = *(float*)&decrypted_hp;
                        if (hp_val == hp_val && hp_val >= 0.0f && hp_val <= 1.0f) e->health = hp_val;
                        else if (hp_val > 1.0f) e->health = 1.0f;
                    }
                }
                if (sh_rva) {
                    UINT64 xor_key = get_cached_xor_key(sh_rva, GetDestiny2Base());
                    if (xor_key) {
                        UINT32 decrypted_sh = raw_sh ^ (UINT32)xor_key;
                        float sh_val = *(float*)&decrypted_sh;
                        if (sh_val == sh_val && sh_val >= 0.0f && sh_val <= 1.0f) e->shield = sh_val;
                        else if (sh_val > 1.0f) e->shield = 1.0f;
                    }
                }
            }
        }
    }
    return filled;
}

BOOL Skeleton_GetCachedLPRootPos(float out[3])
{
    if (!out) return FALSE;
    int lpIdx = LP_GetLocalPlayerIndex();
    if (lpIdx < 0 || lpIdx >= TL_MAX_SLOTS) return FALSE;

    DWORD now = GetTickCount();
    if (now - s_boneCache[lpIdx].lastValidTick < 100u) {
        float *rpos = s_boneCache[lpIdx].rootPos;
        if (rpos[0] != 0.0f || rpos[1] != 0.0f || rpos[2] != 0.0f) {
            out[0] = rpos[0];
            out[1] = rpos[1];
            out[2] = rpos[2];
            return TRUE;
        }
    }
    return FALSE;
}

BOOL Skeleton_GetCachedLPHeadPos(float out[3])
{
    if (!out) return FALSE;
    int lpIdx = LP_GetLocalPlayerIndex();
    if (lpIdx < 0 || lpIdx >= TL_MAX_SLOTS) return FALSE;

    DWORD now = GetTickCount();
    if (now - s_boneCache[lpIdx].lastValidTick < 100u && s_boneCache[lpIdx].boneCount > 18) {
        TlVec3 *head = &s_boneCache[lpIdx].bones[18];
        if (head->x != 0.0f || head->y != 0.0f || head->z != 0.0f) {
            out[0] = head->x;
            out[1] = head->y;
            out[2] = head->z;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL Skeleton_SlotHasBones(int slotIndex)
{
    if (slotIndex < 0 || slotIndex >= TL_MAX_SLOTS) return FALSE;
    DWORD now = GetTickCount();
    return (now - s_boneCache[slotIndex].lastValidTick < 250u && s_boneCache[slotIndex].boneCount > 0);
}

}

#pragma optimize("", on)
