#include "seraph_ptr_crypt.h"
#include <bcrypt.h>
#include <intrin.h>

#pragma comment(lib, "bcrypt.lib")

UINT32 g_seraphObfRoundKeys[27] = {0};
UINT32 g_seraphKeyMask = 0;
UINT64 g_seraphTweakMask = 0;
UINT64 g_seraphMacKey = 0;
volatile LONG g_seraphPtrInited = 0;

static SRWLOCK g_seraphPtrLock = SRWLOCK_INIT;

/* SPECK64/128 key schedule derivation */
static void Speck64_KeySchedule(const UINT32* K, UINT32* roundKeys) {
    UINT32 k = K[0];
    UINT32 l[3] = { K[1], K[2], K[3] };
    
    roundKeys[0] = k;
    for (unsigned int i = 0; i < 26; i++) {
        UINT32 idx = i % 3;
        UINT32 tmp = (_seraph_ror32(l[idx], 8) + k) ^ i;
        k = _seraph_rol32(k, 3) ^ tmp;
        l[idx] = tmp;
        roundKeys[i + 1] = k;
    }
}

void SeraphPtr_Init(void) {
    if (g_seraphPtrInited == 2) return;
    
    AcquireSRWLockExclusive(&g_seraphPtrLock);
    if (g_seraphPtrInited == 0) {
        g_seraphPtrInited = 1; /* state: initializing */
        
        UINT32 K[4] = {0};
        UINT32 entropy[4] = {0};
        
        /* Cryptographically secure seed generation using BCryptGenRandom */
        if (BCryptGenRandom(NULL, (PUCHAR)K, sizeof(K), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            /* Fallback high-entropy generation using hardware clock, QPC, ASLR, and process IDs */
            LARGE_INTEGER qpc;
            QueryPerformanceCounter(&qpc);
            FILETIME ft;
            GetSystemTimeAsFileTime(&ft);
            
            entropy[0] = (UINT32)GetTickCount() ^ ft.dwLowDateTime;
            entropy[1] = (UINT32)qpc.LowPart ^ ft.dwHighDateTime;
            entropy[2] = (UINT32)(ULONG_PTR)&g_seraphPtrInited ^ GetCurrentProcessId();
            entropy[3] = (UINT32)(ULONG_PTR)K ^ GetCurrentThreadId();
            
#if defined(_M_AMD64) || defined(_M_IX86)
            entropy[1] ^= (UINT32)__rdtsc();
#endif
            
            /* Feistel-like mixing step to distribute entropy across the key words */
            for (int i = 0; i < 4; i++) {
                UINT32 h = entropy[i] ^ 0x9E3779B9u;
                h = _seraph_rol32(h, 13) * 0x85EBCA6Bu;
                K[i] = h ^ (h >> 15);
            }
        }
        
        /* Generate dynamic masks for key obfuscation, tweak diversification, and MAC key */
        UINT64 masks[3] = {0};
        if (BCryptGenRandom(NULL, (PUCHAR)masks, sizeof(masks), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0) {
            g_seraphKeyMask   = (UINT32)masks[0];
            g_seraphTweakMask = masks[1];
            g_seraphMacKey    = masks[2];
        } else {
            g_seraphKeyMask   = K[0] ^ K[1];
            g_seraphTweakMask = ((UINT64)K[2] << 32) | K[3];
            g_seraphMacKey    = g_seraphTweakMask ^ 0x9E3779B97F4A7C15ULL;
        }

        /* Calculate round keys and apply memory obfuscation mask */
        UINT32 tempKeys[27] = {0};
        Speck64_KeySchedule(K, tempKeys);
        for (int i = 0; i < 27; i++) {
            g_seraphObfRoundKeys[i] = tempKeys[i] ^ g_seraphKeyMask;
        }

        /* Securely wipe temporary materials from stack */
        SecureZeroMemory(K, sizeof(K));
        SecureZeroMemory(entropy, sizeof(entropy));
        SecureZeroMemory(tempKeys, sizeof(tempKeys));
        SecureZeroMemory(masks, sizeof(masks));

        /* Memory barrier to ensure keys and masks are fully written before state becomes 2 */
        MemoryBarrier();

        g_seraphPtrInited = 2; /* state: fully initialized */
    }
    ReleaseSRWLockExclusive(&g_seraphPtrLock);
}
