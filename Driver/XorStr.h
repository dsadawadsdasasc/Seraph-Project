#ifndef _XOR_H_
#define _XOR_H_
#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <stdio.h>
#endif

// Global XOR key - defined externally (generated at build time)
#ifndef XOR_KEY
#define XOR_KEY 0x55  // default fallback
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline char* xor_a(char* s, int l, unsigned char k) {
    for (int i = 0; i < l; i++) s[i] ^= (k + (unsigned char)i);
    return s;
}
static inline wchar_t* xor_w(wchar_t* s, int l, unsigned char k) {
    for (int i = 0; i < l; i++) s[i] ^= (k + (unsigned char)i);
    return s;
}

#ifdef __cplusplus
}
template<int N, int K> class XorA {
public:
    char _d[N];
    inline constexpr XorA(const char* s) : _d{} {
        for (int i = 0; i < N; i++) _d[i] = s[i] ^ (K + i);
    }
    inline char* d() {
        for (int i = 0; i < N; i++) _d[i] ^= (K + i);
        return _d;
    }
};
template<int N, int K> class XorW {
public:
    wchar_t _d[N];
    inline constexpr XorW(const wchar_t* s) : _d{} {
        for (int i = 0; i < N; i++) _d[i] = s[i] ^ (K + i);
    }
    inline wchar_t* d() {
        for (int i = 0; i < N; i++) _d[i] ^= (K + i);
        return _d;
    }
};
#define XOR_A(s) (XorA<sizeof(s), XOR_KEY>(s).d())
#define XOR_W(s) (XorW<sizeof(s)/2, XOR_KEY>(s).d())
#else
#define XOR_A(s) xor_a((char[]){s}, sizeof(s), XOR_KEY)
#define XOR_W(s) xor_w((wchar_t[]){s}, sizeof(s)/2, XOR_KEY)
#endif

#ifdef _DEBUG
#ifdef _KERNEL_MODE
#define DBG_PRINT(m, ...) DbgPrint(m, ##__VA_ARGS__)
#else
#define DBG_PRINT(m, ...) { char buf[512]; sprintf(buf, m, ##__VA_ARGS__); OutputDebugStringA(buf); }
#endif
#else
#define DBG_PRINT(m, ...)
#endif

#endif
