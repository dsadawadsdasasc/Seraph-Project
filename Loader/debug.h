#pragma once

// DEBUG SYSTEM - Easy to remove for final builds
// To disable all debug messages, define DISABLE_DEBUG before including this header
// or comment out the ENABLE_DEBUG definition below

// Uncomment to disable debug messages for final build
// #define DISABLE_DEBUG

/* C-1/A-10: ENABLE_DEBUG is active only when NDEBUG is NOT defined.
 * b.bat passes /D "NDEBUG" in production builds (DIAGFLAGS), so all
 * file-logging is automatically silenced in every release build. */
#ifndef NDEBUG
#define ENABLE_DEBUG
#endif

/* Ring buffer is always available — byovd.c uses it even in release mode */
#ifndef _KERNEL_MODE
#include "debug_buffer.h"
#endif

#ifdef ENABLE_DEBUG

// Kernel mode vs User mode detection
#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <wdm.h>

// Kernel mode debug macros
#define DEBUG_PRINT(fmt, ...) \
    DbgPrint("[DEBUG][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define DEBUG_PRINT_W(msg) \
    DbgPrint("[DEBUG][%s:%d] %S\n", __FILE__, __LINE__, msg)

#define DEBUG_PRINT_HEX(prefix, data, len) \
    do { \
        DbgPrint("[DEBUG][%s:%d] %s (%zu bytes): ", __FILE__, __LINE__, prefix, (size_t)len); \
        for(size_t i = 0; i < len && i < 32; i++) { \
            DbgPrint("%02X ", ((unsigned char*)data)[i]); \
        } \
        if(len > 32) DbgPrint("..."); \
        DbgPrint("\n"); \
    } while(0)

#else
// User mode — deferred logging via in-memory ring buffer
#include <stdio.h>
#include <windows.h>
#include "debug_buffer.h"

// All logs go to ring buffer. Also flushed to unified seraph_debug.log.
#define DEBUG_PRINT(fmt, ...) \
    do { \
        char debug_buf[512]; \
        snprintf(debug_buf, sizeof(debug_buf), "[DEBUG][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        DbgBuf_Write(debug_buf); \
        WriteLogFile(debug_buf); \
    } while(0)

#define DEBUG_PRINT_HEX(prefix, data, len) \
    do { \
        char debug_buf[1024]; \
        snprintf(debug_buf, sizeof(debug_buf), "[DEBUG][%s:%d] %s (%zu bytes): ", __FILE__, __LINE__, prefix, (size_t)len); \
        for(size_t i = 0; i < len && i < 32; i++) { \
            char tmp[4]; \
            snprintf(tmp, sizeof(tmp), "%02X ", ((unsigned char*)data)[i]); \
            strcat(debug_buf, tmp); \
        } \
        if(len > 32) strcat(debug_buf, "..."); \
        DbgBuf_Write(debug_buf); \
        WriteLogFile(debug_buf); \
    } while(0)
#endif

// Common macros for both modes
#define DEBUG_ENTER_FUNCTION() DEBUG_PRINT("ENTER %s", __FUNCTION__)
#define DEBUG_EXIT_FUNCTION() DEBUG_PRINT("EXIT %s", __FUNCTION__)
/* ERROR triggers immediate flush of ring buffer to disk */
#define DEBUG_ERROR(fmt, ...) \
    do { \
        char _ebuf[768]; \
        snprintf(_ebuf, sizeof(_ebuf), "[ERROR][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        DbgBuf_Write(_ebuf); \
        DbgBuf_Flush("svc_err.log"); \
        WriteLogFile(_ebuf); \
    } while(0)
#define DEBUG_SUCCESS(fmt, ...) DEBUG_PRINT("[SUCCESS] " fmt, ##__VA_ARGS__)

/* Per-module dedicated log files (each module gets its own .log) */
#define DEBUG_STEALTH(fmt, ...)   DEBUG_LOG_TO("stealth_debug.log",  "STEALTH",  fmt, ##__VA_ARGS__)
#define DEBUG_PIIDCACHE(fmt, ...) DEBUG_LOG_TO("piid_debug.log",     "PIID",     fmt, ##__VA_ARGS__)
#define DEBUG_DRIVER(fmt, ...)    DEBUG_LOG_TO("driver_debug.log",   "DRIVER",   fmt, ##__VA_ARGS__)
#define DEBUG_BYOVD(fmt, ...)     ((void)0)
#define DEBUG_EVASION(fmt, ...)   DEBUG_LOG_TO("evasion_debug.log",  "EVASION",  fmt, ##__VA_ARGS__)
#define DEBUG_SYSCALL(fmt, ...)   ((void)0)
#define DEBUG_KEYAUTH(fmt, ...)   DEBUG_LOG_TO("keyauth_debug.log",  "KEYAUTH",  fmt, ##__VA_ARGS__)
#define DEBUG_GUI(fmt, ...)       DEBUG_LOG_TO("gui_debug.log",      "GUI",      fmt, ##__VA_ARGS__)

/* ── Per-module log macros — write to BOTH ring buffer AND per-feature .log file.
 *   Ring buffer captures everything for crash dumps (seraph_crash.txt).
 *   Per-feature .log files give immediate visibility per module.            */

#define DEBUG_LOG_TO(fname, tag, fmt, ...) \
    do { \
        char _lbuf[768]; \
        snprintf(_lbuf, sizeof(_lbuf), "[" tag "][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        DbgBuf_Write(_lbuf); \
        WriteLogFileEx(fname, _lbuf); \
    } while(0)

/* Ring-buffer only — no file I/O.  Used for noisy modules. */
#define DEBUG_RB_ONLY(tag, fmt, ...) \
    do { \
        char _rbuf[768]; \
        snprintf(_rbuf, sizeof(_rbuf), "[" tag "][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        DbgBuf_Write(_rbuf); \
    } while(0)

#define DEBUG_HEX_TO(fname, tag, prefix, data, len) \
    do { \
        char _hbuf[1024]; \
        int _hp = snprintf(_hbuf, sizeof(_hbuf), \
            "[" tag "][%s:%d] %s (%d bytes): ", __FILE__, __LINE__, prefix, (int)(len)); \
        for (int _hi = 0; _hi < (int)(len) && _hp < (int)sizeof(_hbuf)-4; _hi++) \
            _hp += snprintf(_hbuf+_hp, sizeof(_hbuf)-_hp, "%02X ", ((unsigned char*)(data))[_hi]); \
        if ((int)(len) > 64) _hp += snprintf(_hbuf+_hp, sizeof(_hbuf)-_hp, "..."); \
        DbgBuf_Write(_hbuf); \
        WriteLogFileEx(fname, _hbuf); \
    } while(0)

#define DEBUG_HEX_TO_LARGE(fname, tag, prefix, data, len) \
    do { \
        char _hbuf[4096]; \
        int _hp = snprintf(_hbuf, sizeof(_hbuf), \
            "[" tag "][%s:%d] %s (%d bytes):\r\n", __FILE__, __LINE__, prefix, (int)(len)); \
        for (int _hi = 0; _hi < (int)(len) && _hp < (int)sizeof(_hbuf)-6; _hi++) { \
            _hp += snprintf(_hbuf+_hp, sizeof(_hbuf)-_hp, "%02X ", ((unsigned char*)(data))[_hi]); \
            if ((_hi + 1) % 16 == 0) _hp += snprintf(_hbuf+_hp, sizeof(_hbuf)-_hp, "\r\n"); \
        } \
        DbgBuf_Write(_hbuf); \
        WriteLogFileEx(fname, _hbuf); \
    } while(0)

/* cave_finder.c  → disabled */
#define DEBUG_CAVE(fmt, ...)            ((void)0)
#define DEBUG_CAVE_HEX(pfx,data,len)   ((void)0)
/* lazyhook.c     → lazyhook_debug.log */
#define DEBUG_HOOK(fmt, ...)    DEBUG_LOG_TO("lazyhook_debug.log", "HOOK", fmt, ##__VA_ARGS__)
#define DEBUG_HOOK_HEX(pfx,data,len) ((void)0)
/* patch.c/d2_patches.c → disabled */
#define DEBUG_PATCH(fmt, ...)           ((void)0)
#define DEBUG_PATCH_HEX(pfx,data,len)  ((void)0)
/* lists.h (Ticket) → ticket_debug.log  */
#define DEBUG_TICKET(fmt, ...) DEBUG_LOG_TO("ticket_debug.log", "TICKET", fmt, ##__VA_ARGS__)
/* lists.h (Tiger ID acquisition) → tigerid_debug.log */
#define DEBUG_TIGERID(fmt, ...) DEBUG_LOG_TO("tigerid_debug.log", "TIGERID", fmt, ##__VA_ARGS__)
/* Dedicated log for restructured Havok + Fly process */
#define DEBUG_HAVOK(fmt, ...)  DEBUG_LOG_TO("havok_fly.log", "HAVOK", fmt, ##__VA_ARGS__)
#define DEBUG_FLY(fmt, ...)    DEBUG_LOG_TO("havok_fly.log", "FLY",   fmt, ##__VA_ARGS__)
/* local_player.c → local_player_debug.log */
#define DEBUG_LP(fmt, ...)      DEBUG_LOG_TO("local_player_debug.log", "LP", fmt, ##__VA_ARGS__)

/* immune_boss.c  → immune_boss.log */
#define DEBUG_IB(fmt, ...)     DEBUG_LOG_TO("immune_boss.log", "IB", fmt, ##__VA_ARGS__)

/* damage.c       → disabled */
#define DEBUG_DAMAGE(fmt, ...)          ((void)0)

/* guardian.c     → guardian_debug.log                */
#define DEBUG_GSIZE(fmt, ...)           DEBUG_LOG_TO("guardian_debug.log", "GSIZE", fmt, ##__VA_ARGS__)

/* gamespeed.c    → disabled */
#define DEBUG_GS(fmt, ...)              ((void)0)

/* aura.c         → aura_debug.log                    */
#define DEBUG_AURA(fmt, ...)            DEBUG_LOG_TO("aura_debug.log", "AURA", fmt, ##__VA_ARGS__)

/* weapon_stats.c → weapons.log */
#define DEBUG_WEAPONS(fmt, ...)         DEBUG_LOG_TO("weapons.log", "WEAPONS", fmt, ##__VA_ARGS__)
#define DEBUG_WEAPONS_HEX(pfx,data,len) DEBUG_HEX_TO_LARGE("weapons.log", "WEAPONS", pfx, data, len)


/* esp.c          → seraph_esp.log (unified with WriteEspLog) */
#define DEBUG_ESP(fmt, ...)             DEBUG_LOG_TO("seraph_esp.log", "ESP",  fmt, ##__VA_ARGS__)

/* esp.c trace    → fly_debug.log (piggyback on fly log to avoid CWD issues) */
#define DEBUG_TRACE(fmt, ...)           DEBUG_LOG_TO("fly_debug.log", "TRACE", fmt, ##__VA_ARGS__)

/* namechanger.c  → namechanger_debug.log             */
#define DEBUG_NC(fmt, ...)              DEBUG_LOG_TO("namechanger_debug.log", "NC", fmt, ##__VA_ARGS__)
#define DEBUG_NC_HEX(pfx,data,len)     DEBUG_HEX_TO("namechanger_debug.log", "NC", pfx, data, len)

/* WLF / WLFF: WriteLogFile wrappers that are completely stripped in release.
 * In debug builds they forward to WriteLogFile. The key difference vs calling
 * WriteLogFile directly is that WLF("string") in a release build causes the
 * compiler to see ((void)0) — the string literal is never evaluated and the
 * MSVC optimiser does NOT emit it into .rdata.  Direct WriteLogFile("string")
 * calls leave the literal in .rdata even when WriteLogFile is a no-op. */
#define WLF(s)        WriteLogFile(s)
#define WLFF(fmt,...) do { char _wlf[128]; wsprintfA(_wlf,fmt,__VA_ARGS__); WriteLogFile(_wlf); } while(0)

#else

// Empty macros when debug is disabled — NO file I/O whatsoever
#define DEBUG_PRINT(fmt, ...) ((void)0)
#define DEBUG_PRINT_HEX(prefix, data, len) ((void)0)
#define DEBUG_ENTER_FUNCTION() ((void)0)
#define DEBUG_EXIT_FUNCTION() ((void)0)
#define DEBUG_ERROR(fmt, ...) ((void)0)
#define DEBUG_SUCCESS(fmt, ...) ((void)0)
#define DEBUG_STEALTH(fmt, ...)   ((void)0)
#define DEBUG_PIIDCACHE(fmt, ...) ((void)0)
#define DEBUG_DRIVER(fmt, ...)    ((void)0)
#define DEBUG_BYOVD(fmt, ...)     ((void)0)
#define DEBUG_EVASION(fmt, ...)   ((void)0)
#define DEBUG_SYSCALL(fmt, ...)   ((void)0)
#define DEBUG_KEYAUTH(fmt, ...)   ((void)0)
#define DEBUG_GUI(fmt, ...)       ((void)0)
#define DEBUG_LOG_TO(fname, tag, fmt, ...) ((void)0)
#define DEBUG_HEX_TO(fname, tag, prefix, data, len) ((void)0)
#define DEBUG_HEX_TO_LARGE(fname, tag, prefix, data, len) ((void)0)
#define DEBUG_RB_ONLY(tag, fmt, ...) ((void)0)
#define DEBUG_CAVE(fmt, ...) ((void)0)
#define DEBUG_CAVE_HEX(pfx,data,len) ((void)0)
#define DEBUG_HOOK(fmt, ...) ((void)0)
#define DEBUG_HOOK_HEX(pfx,data,len) ((void)0)
#define DEBUG_PATCH(fmt, ...) ((void)0)
#define DEBUG_PATCH_HEX(pfx,data,len) ((void)0)
#define DEBUG_FLY(fmt, ...) ((void)0)
#define DEBUG_FLY_HEX(pfx,data,len) ((void)0)
#define DEBUG_TICKET(fmt, ...) ((void)0)
#define DEBUG_TIGERID(fmt, ...) ((void)0)
#define DEBUG_TICKET_HEX(pfx,data,len) ((void)0)
#define DEBUG_HAVOK(fmt, ...) ((void)0)
#define DEBUG_HAVOK_HEX(pfx,data,len) ((void)0)
#define DEBUG_LP(fmt, ...) ((void)0)
#define DEBUG_DAMAGE(fmt, ...) ((void)0)
#define DEBUG_IB(fmt, ...)     ((void)0)
#define DEBUG_GSIZE(fmt, ...) ((void)0)
#define DEBUG_GS(fmt, ...) ((void)0)
#define DEBUG_AURA(fmt, ...) ((void)0)
#define DEBUG_ESP(fmt, ...)  ((void)0)
#define DEBUG_TRACE(fmt, ...) ((void)0)
#define DEBUG_NC(fmt, ...)   ((void)0)
#define DEBUG_NC_HEX(pfx,data,len) ((void)0)
#define DEBUG_WEAPONS(fmt, ...) ((void)0)
#define DEBUG_WEAPONS_HEX(pfx,data,len) ((void)0)
#define WLF(s)        ((void)0)
#define WLFF(fmt,...) ((void)0)
#define WriteLogFile(msg)           ((void)0)
#define WriteLogFileEx(fname, msg)  ((void)0)
#endif

// Helper function to log NTSTATUS values
static inline void DEBUG_NTSTATUS(const char* prefix, NTSTATUS status) {
#ifdef ENABLE_DEBUG
    // Define NT_SUCCESS locally if not defined
    #ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
    #endif
    #ifdef _KERNEL_MODE
    DbgPrint("%s: 0x%08X %s\n", prefix, status,
             NT_SUCCESS(status) ? "SUCCESS" : "FAILURE");
    #else
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: 0x%08X %s\n", prefix, status,
             NT_SUCCESS(status) ? "SUCCESS" : "FAILURE");
    DbgBuf_Write(buf);
    #endif
#endif
}

// Helper function to log last error (user mode only)
static inline void DEBUG_LASTERROR(const char* prefix) {
#ifdef ENABLE_DEBUG
    #ifndef _KERNEL_MODE
    DWORD err = GetLastError();
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: GetLastError = %lu (0x%08lX)\n", prefix, err, err);
    DbgBuf_Write(buf);
    #endif
#endif
}

#ifndef _KERNEL_MODE
static inline HMODULE GetKernel32Handle(void) {
    static const USHORT k32_enc[] = { 0xCE, 0xC0, 0xD7, 0xCB, 0xC0, 0xC9, 0x96, 0x97, 0x8B, 0xC1, 0xC9, 0xC9, 0x00 };
    WCHAR k32_dec[13];
    for (int i = 0; i < 12; i++) {
        k32_dec[i] = (WCHAR)(k32_enc[i] ^ 0xA5);
    }
    k32_dec[12] = 0;
    return GetModuleHandleW(k32_dec);
}

static inline HMODULE WINAPI DynLoadLibraryW(LPCWSTR lpLibFileName) {
    HMODULE hK32 = GetKernel32Handle();
    if (!hK32) return NULL;
    static const unsigned char fn_enc[] = { 0xE9, 0xCA, 0xC4, 0xC1, 0xE9, 0xCC, 0xC7, 0xD7, 0xC4, 0xD7, 0xDC, 0xF2, 0x00 };
    char fn_dec[13];
    for (int i = 0; i < 12; i++) {
        fn_dec[i] = (char)(fn_enc[i] ^ 0xA5);
    }
    fn_dec[12] = 0;
    typedef HMODULE(WINAPI* tLoadLibraryW)(LPCWSTR);
    tLoadLibraryW pLoadLibraryW = (tLoadLibraryW)GetProcAddress(hK32, fn_dec);
    if (!pLoadLibraryW) return NULL;
    return pLoadLibraryW(lpLibFileName);
}

static inline HMODULE WINAPI DynLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE hK32 = GetKernel32Handle();
    if (!hK32) return NULL;
    static const unsigned char fn_enc[] = { 0xE9, 0xCA, 0xC4, 0xC1, 0xE9, 0xCC, 0xC7, 0xD7, 0xC4, 0xD7, 0xDC, 0xE0, 0xDD, 0xF2, 0x00 };
    char fn_dec[15];
    for (int i = 0; i < 14; i++) {
        fn_dec[i] = (char)(fn_enc[i] ^ 0xA5);
    }
    fn_dec[14] = 0;
    typedef HMODULE(WINAPI* tLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
    tLoadLibraryExW pLoadLibraryExW = (tLoadLibraryExW)GetProcAddress(hK32, fn_dec);
    if (!pLoadLibraryExW) return NULL;
    return pLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

static inline HMODULE WINAPI DynLoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE hK32 = GetKernel32Handle();
    if (!hK32) return NULL;
    static const unsigned char fn_enc[] = { 0xE9, 0xCA, 0xC4, 0xC1, 0xE9, 0xCC, 0xC7, 0xD7, 0xC4, 0xD7, 0xDC, 0xE4, 0x00 };
    char fn_dec[13];
    for (int i = 0; i < 12; i++) {
        fn_dec[i] = (char)(fn_enc[i] ^ 0xA5);
    }
    fn_dec[12] = 0;
    typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
    tLoadLibraryA pLoadLibraryA = (tLoadLibraryA)GetProcAddress(hK32, fn_dec);
    if (!pLoadLibraryA) return NULL;
    return pLoadLibraryA(lpLibFileName);
}

static inline HMODULE WINAPI DynLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE hK32 = GetKernel32Handle();
    if (!hK32) return NULL;
    static const unsigned char fn_enc[] = { 0xE9, 0xCA, 0xC4, 0xC1, 0xE9, 0xCC, 0xC7, 0xD7, 0xC4, 0xD7, 0xDC, 0xE0, 0xDD, 0xE4, 0x00 };
    char fn_dec[15];
    for (int i = 0; i < 14; i++) {
        fn_dec[i] = (char)(fn_enc[i] ^ 0xA5);
    }
    fn_dec[14] = 0;
    typedef HMODULE(WINAPI* tLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
    tLoadLibraryExA pLoadLibraryExA = (tLoadLibraryExA)GetProcAddress(hK32, fn_dec);
    if (!pLoadLibraryExA) return NULL;
    return pLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

static inline BOOL WINAPI DynFreeLibrary(HMODULE hLibModule) {
    HMODULE hK32 = GetKernel32Handle();
    if (!hK32) return FALSE;
    static const unsigned char fn_enc[] = { 0xE3, 0xD7, 0xC0, 0xC0, 0xE9, 0xCC, 0xC7, 0xD7, 0xC4, 0xD7, 0xDC, 0x00 };
    char fn_dec[12];
    for (int i = 0; i < 11; i++) {
        fn_dec[i] = (char)(fn_enc[i] ^ 0xA5);
    }
    fn_dec[11] = 0;
    typedef BOOL(WINAPI* tFreeLibrary)(HMODULE);
    tFreeLibrary pFreeLibrary = (tFreeLibrary)GetProcAddress(hK32, fn_dec);
    if (!pFreeLibrary) return FALSE;
    return pFreeLibrary(hLibModule);
}

#undef LoadLibraryW
#undef LoadLibraryExW
#undef LoadLibraryA
#undef LoadLibraryExA
#undef FreeLibrary

#define LoadLibraryW DynLoadLibraryW
#define LoadLibraryExW DynLoadLibraryExW
#define LoadLibraryA DynLoadLibraryA
#define LoadLibraryExA DynLoadLibraryExA
#define FreeLibrary DynFreeLibrary
#endif