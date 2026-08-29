#pragma once
#include <stdint.h>
#include <intrin.h>
#include <windows.h>
#include "ThemidaSDK.h"

#pragma pack(push, 1)
typedef struct {
    volatile uint32_t obfuscated_data; // encrypted L and R 16-bit halves
    volatile uint32_t mask;            // local random seed/mask
    volatile uint32_t verification;    // contextual integrity checksum (stable)
} SecureVal96;
#pragma pack(pop)

// Reversible LCG mathematical constants
#define LCG_A 0x343FD5ULL
#define LCG_C 0x269EC3ULL
#define LCG_AINV 0x44C9017DULL

// Inline 16-bit rotation functions safe against undefined behavior (UB)
static __inline uint16_t seraph_rotl16(uint16_t x, int r) {
    r &= 15;
    if (r == 0) return x;
    return (uint16_t)((x << r) | (x >> (16 - r)));
}

static __inline uint16_t seraph_rotr16(uint16_t x, int r) {
    r &= 15;
    if (r == 0) return x;
    return (uint16_t)((x >> r) | (x << (16 - r)));
}

// Murmur3-like hash to mix context deterministically per object
static __inline uint32_t _HashContext(uint32_t mask, uintptr_t storage) {
    uint64_t mix = (uint64_t)mask ^ (uint64_t)storage;
    mix ^= mix >> 33;
    mix *= 0xFF51AFD7ED558CCDULL;
    mix ^= mix >> 33;
    mix *= 0xC4CEB9FE1A85EC53ULL;
    mix ^= mix >> 33;
    return (uint32_t)mix;
}

// Write (SPECK32-Variant cipher with keys in registers - No caller dependency)
__forceinline void _SecureWrite64_Impl(SecureVal96* storage, uint32_t real_value) {
    // Generate local random seed/mask for the object
    unsigned int mask = 0;
    if (_rdrand32_step(&mask) == 0) {
        mask = (unsigned int)__rdtsc();
    }
    
    uint16_t L = (uint16_t)(real_value >> 16);
    uint16_t R = (uint16_t)(real_value & 0xFFFF);
    
    // Register key derivation
    uint32_t ks = _HashContext(mask, (uintptr_t)storage);
    
    // 16 Rounds ARX
    for (int r = 0; r < 16; r++) {
        ks = (uint32_t)((ks * LCG_A + LCG_C) & 0xFFFFFFFFULL);
        uint16_t round_key = (uint16_t)(ks ^ (ks >> 16));
        
        L = (uint16_t)((seraph_rotr16(L, 7) + R) ^ round_key);
        R = (uint16_t)(seraph_rotl16(R, 2) ^ L);
    }
    
    storage->obfuscated_data = ((uint32_t)L << 16) | R;
    storage->mask = mask;
    storage->verification = _HashContext(real_value, (uintptr_t)storage) ^ mask;
}

// Read (Decipher with reverse Keygen directly in registers - No caller dependency)
__forceinline uint32_t _SecureRead64_Impl(const SecureVal96* storage) {
    uint32_t val = 0;
    
    uint32_t mask = storage->mask;
    uint32_t data = storage->obfuscated_data;
    
    uint16_t L = (uint16_t)(data >> 16);
    uint16_t R = (uint16_t)(data & 0xFFFF);
    
    uint32_t ks = _HashContext(mask, (uintptr_t)storage);
    
    // Advance LCG to the end
    for (int r = 0; r < 16; r++) {
        ks = (uint32_t)((ks * LCG_A + LCG_C) & 0xFFFFFFFFULL);
    }
    
    // Decode going backward in LCG
    for (int r = 15; r >= 0; r--) {
        uint16_t round_key = (uint16_t)(ks ^ (ks >> 16));
        R = seraph_rotr16(R ^ L, 2);
        L = seraph_rotl16((uint16_t)(L ^ round_key) - R, 7);
        
        if (r > 0) {
            ks = (uint32_t)(((ks - LCG_C) & 0xFFFFFFFFULL) * LCG_AINV);
        }
    }
    
    uint32_t real_val = ((uint32_t)L << 16) | R;
    uint32_t expected_verification = _HashContext(real_val, (uintptr_t)storage) ^ mask;
    
    if (storage->verification == expected_verification) {
        val = real_val;
    } else {
        val = 0; // If corrupted, degrade silently without DoS
    }
    
    return val;
}

// Static Read (Decipher pre-calculated constants at build time without dynamic ASLR)
static __inline uint32_t _SecureReadStatic_Impl(const SecureVal96* storage) {
    uint32_t val = 0;
    
    uint32_t mask = storage->mask;
    uint32_t data = storage->obfuscated_data;
    
    uint16_t L = (uint16_t)(data >> 16);
    uint16_t R = (uint16_t)(data & 0xFFFF);
    
    uint32_t ks = _HashContext(mask, 0); // Pass 0 as storage to make it static
    
    // Advance LCG to the end
    for (int r = 0; r < 16; r++) {
        ks = (uint32_t)((ks * LCG_A + LCG_C) & 0xFFFFFFFFULL);
    }
    
    // Decode going backward in LCG
    for (int r = 15; r >= 0; r--) {
        uint16_t round_key = (uint16_t)(ks ^ (ks >> 16));
        R = seraph_rotr16(R ^ L, 2);
        L = seraph_rotl16((uint16_t)(L ^ round_key) - R, 7);
        
        if (r > 0) {
            ks = (uint32_t)(((ks - LCG_C) & 0xFFFFFFFFULL) * LCG_AINV);
        }
    }
    
    uint32_t real_val = ((uint32_t)L << 16) | R;
    uint32_t expected_verification = _HashContext(real_val, 0) ^ mask;
    
    if (storage->verification == expected_verification) {
        val = real_val;
    } else {
        val = 0;
    }
    
    return val;
}

#define SecureWrite(storage_ptr, val) _SecureWrite64_Impl(storage_ptr, (uint32_t)(val))
#define SecureRead(storage_ptr)       _SecureRead64_Impl(storage_ptr)
#define SecureReadStatic(storage_ptr) _SecureReadStatic_Impl(storage_ptr)
