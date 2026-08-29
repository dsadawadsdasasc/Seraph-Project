#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern UINT32 g_seraphObfRoundKeys[27];
extern UINT32 g_seraphKeyMask;
extern UINT64 g_seraphTweakMask;
extern UINT64 g_seraphMacKey;
extern volatile LONG g_seraphPtrInited;

/* 32-bit rotate helpers */
#define _seraph_ror32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define _seraph_rol32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

/* 64-bit rotate helper */
static inline UINT64 _seraph_ror64(UINT64 v, int n) {
    n &= 63; return n ? ((v >> n) | (v << (64 - n))) : v;
}

/* Initialize ARX pointer encryption seeds */
void SeraphPtr_Init(void);

/* Fast 16-bit MAC helper for pointer authentication */
static inline UINT16 _seraph_compute_mac(UINT64 address, UINT64 storageVA) {
    UINT64 h = address ^ storageVA ^ g_seraphMacKey;
    h ^= (h >> 21);
    h *= 0x9E3779B97F4A7C15ULL;
    h ^= (h >> 37);
    return (UINT16)(h ^ (h >> 16) ^ (h >> 32) ^ (h >> 48));
}

/* Encrypt a raw pointer for storage at target StorageVA using Authenticated SPECK64/128 */
static inline UINT64 SeraphPtr_Encrypt(PVOID ptr, UINT64 storageVA) {
    if (g_seraphPtrInited != 2) SeraphPtr_Init();

    UINT64 address = (UINT64)ptr;
    
    /* Authenticate the entire 64-bit value to support sign-extended, kernel, or malformed pointers */
    UINT16 mac = _seraph_compute_mac(address, storageVA);
    
    /* Embed the MAC into the high 16 bits of the plaintext */
    UINT64 plain = (address & 0x0000FFFFFFFFFFFFULL) | ((UINT64)mac << 48);
    
    /* Apply key-diversified tweak */
    UINT64 tweak = storageVA ^ g_seraphTweakMask;
    UINT64 val = plain ^ tweak;
    
    UINT32 y = (UINT32)val;
    UINT32 x = (UINT32)(val >> 32);

    /* SPECK64/128 Encryption: 27 rounds with dynamic key de-obfuscation */
    for (int i = 0; i < 27; i++) {
        UINT32 roundKey = g_seraphObfRoundKeys[i] ^ g_seraphKeyMask;
        x = (_seraph_ror32(x, 8) + y) ^ roundKey;
        y = _seraph_rol32(y, 3) ^ x;
    }

    UINT64 cipher = ((UINT64)x << 32) | y;
    return cipher ^ tweak;
}

/* Decrypt an encrypted pointer stored at StorageVA directly into a register */
static inline PVOID SeraphPtr_Decrypt(UINT64 encPtr, UINT64 storageVA) {
    if (g_seraphPtrInited != 2) SeraphPtr_Init();
    
    /* An uninitialized (zeroed) pointer in memory decrypts to NULL */
    if (!encPtr) return NULL;

    /* Apply key-diversified tweak */
    UINT64 tweak = storageVA ^ g_seraphTweakMask;
    UINT64 val = encPtr ^ tweak;
    
    UINT32 y = (UINT32)val;
    UINT32 x = (UINT32)(val >> 32);

    /* SPECK64/128 Decryption: 27 rounds in reverse */
    for (int i = 26; i >= 0; i--) {
        UINT32 roundKey = g_seraphObfRoundKeys[i] ^ g_seraphKeyMask;
        y = _seraph_ror32(y ^ x, 3);
        x = _seraph_rol32((x ^ roundKey) - y, 8);
    }

    UINT64 plain = (((UINT64)x << 32) | y) ^ tweak;
    UINT64 address = plain & 0x0000FFFFFFFFFFFFULL;
    UINT16 storedMac = (UINT16)(plain >> 48);

    /* Verify MAC to check integrity (branchless check for authenticated blocks) */
    UINT16 expectedMac = _seraph_compute_mac(address, storageVA);
    if (storedMac != expectedMac) {
        /* Tampering detected! Return NULL to prevent exploitation (or trigger crash) */
        return NULL;
    }

    return (PVOID)address;
}

#define SERAPH_ENC_PTR(ptr, storageVA) ((UINT64)(ptr))
#define SERAPH_DEC_PTR(enc, storageVA) ((PVOID)(enc))

#ifdef __cplusplus
}
#endif
