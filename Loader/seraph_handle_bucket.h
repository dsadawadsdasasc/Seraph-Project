#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Total capacity: 64 buckets * 1024 slots = 65,536 handles.
 * High 19 bits: bucket index
 * Low 10 bits: slot index within bucket */
#define SHB_BUCKET_COUNT   64
#define SHB_SLOT_COUNT     1024
#define SHB_SLOT_MASK      0x3FF  /* 1023 slots per bucket */
#define SHB_SLOT_BITS      10

typedef struct {
    UINT64 encEntries;   /* Entries array VA ^ g_shbSeed */
    UINT32 stride;       /* Size of each slot entry      */
    UINT64 salt;         /* Per-bucket cryptographically random XOR salt */
} SeraphBucket;

typedef struct {
    UINT64 encPtr;       /* Object pointer XOR'd with (salt ^ handle) */
    UINT64 checksum;     /* Integrity checksum: Mix64(ptr) ^ handle ^ salt */
    UINT32 cookie;       /* High-entropy validation cookie (upper 15 bits of handle) */
    BOOL   occupied;     /* Explicit occupancy flag */
} SeraphSlot;

/* Initialize the handle bucket system with a random seed. */
void SeraphHB_Init(void);

/* Insert an object pointer into the handle bucket. Returns a 32-bit handle. */
INT32 SeraphHB_Insert(PVOID ptr);

/* Retrieve and decode the object pointer from a 32-bit handle in O(1) time. */
PVOID SeraphHB_Lookup(INT32 handle);

/* Remove a handle from the bucket table. */
BOOL SeraphHB_Remove(INT32 handle);

#ifdef __cplusplus
}
#endif
