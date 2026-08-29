#include "seraph_handle_bucket.h"
#include "ThemidaSDK.h"
#include <bcrypt.h>
#include <intrin.h>
#include "syscalls.h"  /* SeraphSleep */

#pragma comment(lib, "bcrypt.lib")

#define RtlGenRandom SystemFunction036
#ifdef __cplusplus
extern "C" {
#endif
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
#ifdef __cplusplus
}
#endif

#ifndef FORCEINLINE
#define FORCEINLINE __forceinline
#endif

static SeraphBucket g_shbBuckets[SHB_BUCKET_COUNT] = {0};
static SeraphSlot*  g_shbSlots[SHB_BUCKET_COUNT]   = {0};
static int          g_shbBucketOrder[SHB_BUCKET_COUNT] = {0};
static UINT64       g_shbSeed                       = 0;
static CRITICAL_SECTION g_shbLock;
static BOOL         g_shbInited                     = FALSE;
static volatile LONG g_shbIniting = 0;



static FORCEINLINE BOOL FillRandom(PVOID buf, ULONG len) {
    if (RtlGenRandom(buf, len)) return TRUE;
    if (BCryptGenRandom(NULL, (PUCHAR)buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0) return TRUE;
    return FALSE;
}

/* MurmurHash3 64-bit mixer for checksum calculations */
static FORCEINLINE UINT64 Mix64(UINT64 key) {
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;
    return key;
}

void SeraphHB_Init(void) {
    if (g_shbInited) return;
    if (InterlockedCompareExchange(&g_shbIniting, 1, 0) != 0) {
        while (!g_shbInited) SeraphSleep(1);
        return;
    }
    InitializeCriticalSection(&g_shbLock);


    /* Initialize bucket order */
    for (int i = 0; i < SHB_BUCKET_COUNT; i++) {
        g_shbBucketOrder[i] = i;
    }

    /* Generate cryptographically secure global seed */
    if (!FillRandom(&g_shbSeed, sizeof(g_shbSeed))) {
        /* Fallback seed using high entropy sources */
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        DWORD volSerial = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);
        g_shbSeed = ((UINT64)volSerial << 32) ^ (UINT64)GetTickCount64() ^ (UINT64)qpc.QuadPart ^ (UINT64)__rdtsc() ^ 0x9E3779B97F4A7C15ULL;
    }
    if (g_shbSeed == 0) g_shbSeed = 0xA5C3F1928B4D7E20ULL;

    /* Shuffle bucket order pseudo-randomly */
    for (int i = SHB_BUCKET_COUNT - 1; i > 0; i--) {
        UINT32 randVal = 0;
        if (FillRandom(&randVal, sizeof(randVal))) {
            int j = randVal % (i + 1);
            int temp = g_shbBucketOrder[i];
            g_shbBucketOrder[i] = g_shbBucketOrder[j];
            g_shbBucketOrder[j] = temp;
        }
    }

    BOOL allocSuccess = TRUE;
    for (int i = 0; i < SHB_BUCKET_COUNT; i++) {
        g_shbSlots[i] = (SeraphSlot*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SeraphSlot) * SHB_SLOT_COUNT);
        if (!g_shbSlots[i]) {
            allocSuccess = FALSE;
            break;
        }

        /* Generate cryptographically secure per-bucket salt */
        UINT64 salt = 0;
        if (!FillRandom(&salt, sizeof(salt))) {
            salt = g_shbSeed ^ ((UINT64)(i + 1) * 0x100000001B3ULL) ^ (UINT64)__rdtsc();
        }

        g_shbBuckets[i].encEntries = (UINT64)g_shbSlots[i] ^ g_shbSeed;
        g_shbBuckets[i].stride     = (UINT32)sizeof(SeraphSlot);
        g_shbBuckets[i].salt       = salt;
    }

    if (!allocSuccess) {
        /* Rollback allocated buckets to prevent memory leak and invalid state */
        for (int i = 0; i < SHB_BUCKET_COUNT; i++) {
            if (g_shbSlots[i]) {
                HeapFree(GetProcessHeap(), 0, g_shbSlots[i]);
                g_shbSlots[i] = NULL;
            }
        }
        DeleteCriticalSection(&g_shbLock);
        g_shbIniting = 0;
    } else {
        g_shbInited = TRUE;
    }

}

INT32 SeraphHB_Insert(PVOID ptr) {
    if (!ptr || !g_shbInited) return 0;
    EnterCriticalSection(&g_shbLock);

    INT32 handle = 0;


    for (int idx = 0; idx < SHB_BUCKET_COUNT; idx++) {
        int b = g_shbBucketOrder[idx];
        SeraphSlot* slots = g_shbSlots[b];
        if (!slots) continue;

        for (int s = 0; s < SHB_SLOT_COUNT; s++) {
            /* Reserve b=0, s=0 to prevent handle=0 */
            if (b == 0 && s == 0) continue;

            if (!slots[s].occupied) {
                /* Slot is free — generate random 15-bit cookie (1 to 0x7FFF) */
                UINT32 cookie = 0;
                while (cookie == 0) {
                    if (!FillRandom(&cookie, sizeof(cookie))) {
                        cookie = (UINT32)(__rdtsc() ^ GetTickCount()) & 0x7FFF;
                    } else {
                        cookie &= 0x7FFF;
                    }
                }

                handle = (INT32)(((UINT32)cookie << 16) | ((UINT32)b << SHB_SLOT_BITS) | (UINT32)s);

                UINT64 salt = g_shbBuckets[b].salt;
                UINT64 encPtr = (UINT64)ptr ^ salt ^ (UINT64)(UINT32)handle;

                slots[s].encPtr   = encPtr;
                slots[s].checksum = Mix64((UINT64)ptr) ^ (UINT64)(UINT32)handle ^ salt;
                slots[s].cookie   = cookie;
                slots[s].occupied = TRUE;
                goto _insert_exit;
            }
        }
    }

_insert_exit:
    LeaveCriticalSection(&g_shbLock);
    return handle;
}

PVOID SeraphHB_Lookup(INT32 handle) {
    if (handle <= 0 || !g_shbInited) return NULL;

    /* Acquire lock to ensure thread safety and avoid race conditions with inserts/deletes */
    EnterCriticalSection(&g_shbLock);


    PVOID ptr = NULL;
    UINT32 uHandle = (UINT32)handle;
    UINT32 cookie = uHandle >> 16;
    UINT32 slotIdx = uHandle & SHB_SLOT_MASK;
    UINT32 bucketIdx = (uHandle >> SHB_SLOT_BITS) & (SHB_BUCKET_COUNT - 1);

    const SeraphBucket *b = &g_shbBuckets[bucketIdx];
    UINT64 entries = b->encEntries ^ g_shbSeed;
    if (!entries || !b->stride || !g_shbSlots[bucketIdx]) {
        goto _lookup_fail;
    }

    if (slotIdx >= SHB_SLOT_COUNT) {
        goto _lookup_fail;
    }

    const SeraphSlot *slot = &g_shbSlots[bucketIdx][slotIdx];

    /* Validate slot state and validation cookie */
    if (!slot->occupied || slot->cookie != cookie) {
        goto _lookup_fail;
    }

    /* Decrypt pointer */
    UINT64 rawPtr = slot->encPtr ^ b->salt ^ (UINT64)uHandle;
    if (!rawPtr) {
        goto _lookup_fail;
    }

    /* Validate decrypted pointer range (Handles can be under 0x10000, e.g., 0x4, 0x120) */
    if (rawPtr == 0 || rawPtr >= 0x7FFFFFFFFFFFULL) {
        goto _lookup_fail;
    }

    /* Validate checksum integrity */
    UINT64 expectedChecksum = Mix64(rawPtr) ^ (UINT64)uHandle ^ b->salt;
    if (slot->checksum != expectedChecksum) {
        goto _lookup_fail;
    }

    ptr = (PVOID)rawPtr;
    goto _lookup_exit;

_lookup_fail:
    ptr = NULL;

_lookup_exit:
    LeaveCriticalSection(&g_shbLock);
    return ptr;
}

BOOL SeraphHB_Remove(INT32 handle) {
    if (handle <= 0 || !g_shbInited) return FALSE;
    EnterCriticalSection(&g_shbLock);


    BOOL result = FALSE;
    UINT32 uHandle = (UINT32)handle;
    UINT32 cookie = uHandle >> 16;
    UINT32 slotIdx = uHandle & SHB_SLOT_MASK;
    UINT32 bucketIdx = (uHandle >> SHB_SLOT_BITS) & (SHB_BUCKET_COUNT - 1);

    if (bucketIdx < SHB_BUCKET_COUNT && slotIdx < SHB_SLOT_COUNT && g_shbSlots[bucketIdx]) {
        SeraphSlot *slot = &g_shbSlots[bucketIdx][slotIdx];
        if (slot->occupied && slot->cookie == cookie) {
            slot->encPtr   = 0;
            slot->checksum = 0;
            slot->cookie   = 0;
            slot->occupied = FALSE;
            result = TRUE;
        }
    }

    LeaveCriticalSection(&g_shbLock);
    return result;
}
