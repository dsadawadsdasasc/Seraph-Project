/* skeleton.c — TigerList skeleton reader with thread-safe snapshot for the overlay */
#include "skeleton.h"
#include "tigerlist.h"
#include "esp.h"
#include "esp_overlay.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lists.h"
#include "local_player.h"
#include <string.h>
#include <mmsystem.h>
#include "syscalls.h"  /* SeraphSleep, SeraphCreateThread */
#pragma comment(lib, "winmm.lib")
/* Forward declaration — defined in esp_overlay.cpp */
extern void EspOverlay_PushBoxSnapshot(const EspBox *boxes, int n);

/* Disable compiler optimization for the entire translation unit.
 * Release build (/O2) optimizations aggressively reorder and cache
 * skeleton bone matrices reading and rotation calculations. */
#pragma optimize("", off)


#ifndef NDEBUG
static void _sk_log(const char *msg) {
    char buf[512];
    wsprintfA(buf, "[SKEL][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    OutputDebugStringA(buf);
}
#define SK_LOG(msg) _sk_log(msg)
#else
#define SK_LOG(msg) ((void)0)
#endif

/* Spinlock-protected snapshot consumed by the overlay render thread */
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

/* Background update threads */
static volatile LONG s_threadStarted  = 0;
static volatile LONG s_threadStop     = 0;
static HANDLE        s_skelThread     = NULL;

/* Separate box-update thread — runs ESP_GetEntityBoxes at ~30Hz so it
 * doesn't block the bone thread from reaching ~90Hz update rate. */
static volatile LONG s_boxThreadStarted = 0;
static HANDLE        s_boxThread        = NULL;

static DWORD WINAPI _BoxUpdateThread(LPVOID p)
{
    (void)p;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    /* ~90Hz for boxes — stable visual updates for boxes, health and names */
    while (InterlockedCompareExchange(&s_threadStop, 0, 0) == 0) {
        if (GetDestiny2CR3()) {
            DWORD t0 = timeGetTime();
            EspBox boxes[ESP_MAX_BOXES];
            int bn = ESP_GetEntityBoxes(sw, sh, boxes, ESP_MAX_BOXES);
            EspOverlay_PushBoxSnapshot(boxes, bn);
            DWORD elapsed = timeGetTime() - t0;
            if (elapsed < 11u) SeraphSleep(11u - elapsed);
        } else {
            SeraphSleep(22);
        }
    }
    InterlockedExchange(&s_boxThreadStarted, 0);
    return 0;
}

static DWORD WINAPI _SkelUpdateThread(LPVOID p)
{
    (void)p;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    /* timeBeginPeriod(1) is managed centrally by EspOverlay_Start/Stop.
     * Calling it per-thread would increment the global ref-count multiple
     * times, leaving it active even after one thread exits. */

    /* Cache screen size once — GetSystemMetrics is a syscall, no need per-tick */
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    /* Bone update loop: runs Skeleton_ReadAll + ESP_ReadMatrices as fast as
     * the BYOVD driver allows (~55-90Hz in practice with 12 players).
     * ESP_GetEntityBoxes was moved to _BoxUpdateThread at 30Hz so it no
     * longer blocks this loop — bones are what the aimbot and skeleton ESP
     * need fresh; boxes only need ~30Hz for smooth rendering. */
    while (InterlockedCompareExchange(&s_threadStop, 0, 0) == 0) {
        if (!GetDestiny2CR3()) { SeraphSleep(50); continue; }

        /* Measure loop start for adaptive sleep */
        DWORD t0 = timeGetTime();

        /* Read player skeletons (bones) */
        SkelEntity tmp[SKEL_ENTITY_MAX];
        int count = Skeleton_ReadAll(tmp, SKEL_ENTITY_MAX);

        /* Read view/proj matrix directly from game memory AFTER bones,
         * so the (bones, matrix) pair are from the same moment in time.
         * This eliminates the drift seen when moving. */
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

        /* Adaptive sleep: target ~130 Hz (7 ms/tick).
         * If the loop already consumed >= 7ms, skip sleep entirely. */
        DWORD elapsed = timeGetTime() - t0;
        if (elapsed < 7u) SeraphSleep(7u - elapsed);
    }

    InterlockedExchange(&s_threadStarted, 0);
    InterlockedExchange(&s_threadStop,    0);
    return 0;
}


void Skeleton_StartUpdateThread(void)
{
    if (InterlockedCompareExchange(&s_threadStarted, 1, 0) != 0) return;
    InterlockedExchange(&s_threadStop, 0);
    HANDLE h = SeraphCreateThread(_SkelUpdateThread, NULL);
    if (!h) { InterlockedExchange(&s_threadStarted, 0); return; }
    s_skelThread = h;
    /* Start box update thread alongside bone thread */
    if (InterlockedCompareExchange(&s_boxThreadStarted, 1, 0) == 0) {
        HANDLE hb = SeraphCreateThread(_BoxUpdateThread, NULL);
        if (hb) s_boxThread = hb;
        else InterlockedExchange(&s_boxThreadStarted, 0);
    }
    SK_LOG("StartUpdateThread: started");
}

void Skeleton_StopUpdateThread(void)
{
    /* Signal stop for both threads */
    InterlockedExchange(&s_threadStop, 1);
    if (s_skelThread) {
        WaitForSingleObject(s_skelThread, 2000);
        SysNtClose(s_skelThread);
        s_skelThread = NULL;
    }
    if (s_boxThread) {
        WaitForSingleObject(s_boxThread, 2000);
        SysNtClose(s_boxThread);
        s_boxThread = NULL;
    }
    InterlockedExchange(&s_threadStarted, 0);
    InterlockedExchange(&s_boxThreadStarted, 0);
    _snap_lock();
    s_snapFilled   = 0;
    s_snapMatValid = FALSE;
    _snap_unlock();
    SK_LOG("StopUpdateThread: stopped");
}



/* Read SL (Schindler's List) world pos for slot from a cached SL buffer */
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

static inline UINT32 _rotl32(UINT32 value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

static BYTE rot_key_byte(size_t i) {
    if (i == 0) return 0;
    size_t n = i % 31;
    if (n == 0) {
        return (BYTE)(0x7a136d5eu & 0xFF);
    } else {
        return (BYTE)(_rotl32(0x7a136d5eu, (int)n) & 0xFF);
    }
}

static void decrypt_name(const BYTE *src, char *dst, size_t maxLen) {
    size_t len = 0;
    for (size_t i = 0; i < maxLen - 1; i++) {
        BYTE plain = (BYTE)(91u * (src[i] ^ rot_key_byte(i)));
        dst[i] = (char)plain;
        if (plain == 0) return;
    }
    dst[maxLen - 1] = '\0';
}





/* Name cache — decryption only runs when cipher changes (names are static per match) */
typedef struct { UINT32 key; char name[64]; } NameCacheEntry;
static NameCacheEntry s_nameCache[TL_MAX_SLOTS];

/* Per-slot bone cache to prevent single-frame flickering when memory reads drop momentarily */
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

    /* Batch-read slot headers: team, boneHdl, playerDefHdl, LP pos, hp handle, name */
    typedef struct {
        UINT32 team;
        UINT32 boneHdl;
        UINT32 playerDefHdl;
        UINT32 hpHdl;     /* offset 0x48B0 — HP component handle */
        BYTE   nameCipher[64]; /* offset 0x09D4 — encrypted name */
    } SlotHdr;
    SlotHdr headers[TL_MAX_SLOTS];
    memset(headers, 0, sizeof(headers));

    typedef struct {
        BYTE range1[8];   /* 0x0004 .. 0x000C */
        BYTE range2[84];  /* 0x09D4 .. 0x0A28 */
        BYTE range3[140]; /* 0x48A0 .. 0x492C */
    } SlotBuffers;
    static SlotBuffers slotBufs[TL_MAX_SLOTS]; /* static to prevent large stack growth */
    memset(slotBufs, 0, sizeof(slotBufs));

    BYOVD_READ_BATCH_ENTRY batch[TL_MAX_SLOTS * 3];
    int bc = 0;
    for (int ti = 0; ti < TL_MAX_SLOTS; ti++) {
        UINT64 sv = tlArrPtr + (UINT64)ti * TL_STRIDE;
        batch[bc].va = sv + 0x0004u; batch[bc].buf = slotBufs[ti].range1; batch[bc].size = 8;   bc++;
        batch[bc].va = sv + 0x09D4u; batch[bc].buf = slotBufs[ti].range2; batch[bc].size = 84;  bc++;
        batch[bc].va = sv + 0x48A0u; batch[bc].buf = slotBufs[ti].range3; batch[bc].size = 140; bc++;
    }
    BYOVD_ReadBatch(cr3, batch, bc);

    for (int ti = 0; ti < TL_MAX_SLOTS; ti++) {
        headers[ti].playerDefHdl = *(UINT32*)(slotBufs[ti].range1 + 0);
        
        memcpy(headers[ti].nameCipher, slotBufs[ti].range2 + 0, 64);
        headers[ti].team         = *(UINT32*)(slotBufs[ti].range2 + 80);
        
        headers[ti].boneHdl      = *(UINT32*)(slotBufs[ti].range3 + 0);
        headers[ti].hpHdl        = *(UINT32*)(slotBufs[ti].range3 + 16);
    }

    /* Cache SL buffer for world-position lookup */
    UINT64 slBase = ESP_GetSLListBase();
    static BYTE slBuf[32 * 0x200u];
    BOOL slOk = FALSE;
    if (slBase > 0x10000ULL) {
        BYOVD_LOCK();
        slOk = BYOVD_ReadVA(cr3, slBase, slBuf, sizeof(slBuf));
        BYOVD_UNLOCK();
    }

    /* LP team resolution */
    UINT32 lpTeam = 0;
    INT32  lpIdx  = LP_GetLocalPlayerIndex();
    if (lpIdx >= 0 && lpIdx < TL_MAX_SLOTS) {
        lpTeam = headers[lpIdx].team;
    }

    DWORD nowTick = GetTickCount();
    int filled = 0;
    for (int ti = 0; ti < TL_MAX_SLOTS && filled < max; ti++) {
        BOOL   isLP    = (lpIdx == ti);

        /* Skip slots without a valid bone handle (unless it is the local player) */
        if (!isLP && !is_tiger_handle(headers[ti].boneHdl)) {
            s_boneCache[ti].boneCount = 0;
            continue;
        }

        float  wpos[3] = {0,0,0};
        INT32  team    = (headers[ti].team == lpTeam || isLP) ? 0 : 1;
        BOOL   posOk   = FALSE;

        /* SL lookup — primary source for enemies, fallback for LP */
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

        if (readCount > 0) {
            memcpy(s_boneCache[ti].bones, bones, (size_t)readCount * sizeof(TlVec3));
            memcpy(s_boneCache[ti].boneParents, parents, (size_t)readCount * sizeof(short));
            s_boneCache[ti].boneCount = readCount;
            s_boneCache[ti].rootPos[0] = rpos[0]; s_boneCache[ti].rootPos[1] = rpos[1]; s_boneCache[ti].rootPos[2] = rpos[2];
            s_boneCache[ti].lastValidTick = nowTick;
        } else if (nowTick - s_boneCache[ti].lastValidTick < 250u && s_boneCache[ti].boneCount > 0) {
            readCount = s_boneCache[ti].boneCount;
            memcpy(bones, s_boneCache[ti].bones, (size_t)readCount * sizeof(TlVec3));
            memcpy(parents, s_boneCache[ti].boneParents, (size_t)readCount * sizeof(short));
            rpos[0] = s_boneCache[ti].rootPos[0]; rpos[1] = s_boneCache[ti].rootPos[1]; rpos[2] = s_boneCache[ti].rootPos[2];
        } else {
            s_boneCache[ti].boneCount = 0;
        }

        if (readCount > 0 && !posOk) {
            wpos[0]=bones[0].x; wpos[1]=bones[0].y; wpos[2]=bones[0].z;
            posOk=TRUE;
        }

        /* Skip non-LP entities that do not have valid bones */
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

        /* Decrypt display name — only when cipher changes (names are static per match) */
        {
            UINT32 cKey = 0;
            memcpy(&cKey, headers[ti].nameCipher, 4);
            if (s_nameCache[ti].key != cKey || s_nameCache[ti].name[0] == '\0') {
                decrypt_name(headers[ti].nameCipher, e->name, sizeof(e->name));
                s_nameCache[ti].key = cKey;
                memcpy(s_nameCache[ti].name, e->name, sizeof(e->name));
            } else {
                memcpy(e->name, s_nameCache[ti].name, sizeof(e->name));
            }
        }

        /* If slot is alive, query health and shield values.
         * HP handle at slot+0x48B0. Resolve via datum table → component VA,
         * shield @ +0x0B08, health @ +0x0BF8. */
        e->health = 1.0f;
        e->shield = 0.0f;
        if (headers[ti].hpHdl != 0 && headers[ti].hpHdl != 0xFFFFFFFFu && g_EspState.datum_valid) {
            UINT64 hpComp = esp_datum_resolve(cr3, headers[ti].hpHdl);
            if (hpComp > 0x10000ULL) {
                float sh_val = 0.0f, hp_val = 1.0f;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, hpComp + 0x0B08u, &sh_val, 4);
                BYOVD_ReadVA(cr3, hpComp + 0x0BF8u, &hp_val, 4);
                BYOVD_UNLOCK();
                if (sh_val == sh_val && sh_val >= 0.0f && sh_val <= 1.0f) e->shield = sh_val;
                else if (sh_val > 1.0f) e->shield = 1.0f;
                if (hp_val == hp_val && hp_val >= 0.0f && hp_val <= 1.0f) e->health = hp_val;
                else if (hp_val > 1.0f) e->health = 1.0f;
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

#pragma optimize("", on)
