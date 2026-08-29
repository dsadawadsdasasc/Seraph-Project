#ifndef _XOR_H_
#define _XOR_H_
#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <stdio.h>
#endif

#include "xor_strings.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SERAPH_KEY1
#define SERAPH_KEY1 0x12345678u
#define SERAPH_KEY2 0x87654321u
#define SERAPH_KEY3 0x11223344u
#define SERAPH_KEY4 0x55667788u
#endif

#ifndef _KERNEL_MODE
/* IMPORTANT: __declspec(thread) removed — creates PE TLS entries, breaking
 * CreateThread after UeErasePEHeader().
 * _alloca also rejected — MSVC /Od does NOT inline static inline functions,
 * so _alloca would allocate on the callee frame and the returned pointer
 * would be dangling on return (classic dangling-VLA bug).
 *
 * Solution: per-TU global circular buffer (16 slots, power of 2) indexed
 * by an InterlockedIncrement counter. Zero TLS, zero heap, no dangling
 * pointers. Safe for up to 16 simultaneously in-flight decoded strings
 * (typical usage is 1-4). */
#define _XP_SLOTS  16                          /* must be power of 2 */
#define _XP_BUF    512

static char          _g_xpa[_XP_SLOTS][_XP_BUF];
static wchar_t       _g_xpw[_XP_SLOTS][_XP_BUF];
static volatile LONG _g_xia = 0;
static volatile LONG _g_xiw = 0;

static inline char* xor_pool_a(const char* s, int l) {
    int slot = (int)(InterlockedIncrement(&_g_xia) & (_XP_SLOTS - 1));
    char* d = _g_xpa[slot];
    int cap = (l < _XP_BUF - 1) ? l : _XP_BUF - 1;
    for (int i = 0; i < cap; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        unsigned char kb = (unsigned char)(v3 & 0xFF);
        d[i] = (char)(s[i] ^ kb);
    }
    d[cap] = 0;
    return d;
}

static inline wchar_t* xor_pool_w(const wchar_t* s, int l) {
    int slot = (int)(InterlockedIncrement(&_g_xiw) & (_XP_SLOTS - 1));
    wchar_t* d = _g_xpw[slot];
    int cap = (l < _XP_BUF - 1) ? l : _XP_BUF - 1;
    for (int i = 0; i < cap; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        wchar_t kw = (wchar_t)(v3 & 0xFFFF);
        d[i] = (wchar_t)(s[i] ^ kw);
    }
    d[cap] = 0;
    return d;
}

#else
// Simple in-place for Kernel Mode.
static inline char* xor_str_a(char* s, int l) {
    for (int i = 0; i < l - 1; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        unsigned char kb = (unsigned char)(v3 & 0xFF);
        s[i] ^= kb;
    }
    return s;
}
static inline wchar_t* xor_str_w(wchar_t* s, int l) {
    for (int i = 0; i < l - 1; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        wchar_t kw = (wchar_t)(v3 & 0xFFFF);
        s[i] ^= kw;
    }
    return s;
}
#endif

#ifdef __cplusplus
}
#endif

#ifndef _KERNEL_MODE
#define XOR_A(s) xor_pool_a(s, (int)sizeof(s))
#define XOR_W(s) xor_pool_w(s, (int)sizeof(s)/2)
/* DXOR = Decrypt pre-encrypted array. Array must be const wchar_t[] or const char[]. */
/* -1 so the null terminator byte is NOT XOR'd; xor_pool sets d[l]=0 after the loop. */
#define DXOR_A(arr) xor_pool_a((const char*)(arr), (int)sizeof(arr) - 1)
#define DXOR_W(arr) xor_pool_w((const wchar_t*)(arr), (int)(sizeof(arr)/sizeof(wchar_t)) - 1)
#else
#define XOR_A(s) xor_str_a((char[]){s}, (int)sizeof(s))
#define XOR_W(s) xor_str_w((wchar_t[]){s}, (int)sizeof(s)/2)
#define DXOR_A(arr) xor_str_a((char*)(arr), (int)sizeof(arr) - 1)
#define DXOR_W(arr) xor_str_w((wchar_t*)(arr), (int)(sizeof(arr)/sizeof(wchar_t)) - 1)
#endif

#endif
