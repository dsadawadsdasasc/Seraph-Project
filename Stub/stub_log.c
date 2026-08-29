/* stub_log.c — Real WriteLogFile implementation for Stub.exe.
 *
 * COMPILATION NOTE: this file MUST be compiled with /D SERAPH_STUB_LOG_IMPL
 * (already set in build_stub.bat).  That flag prevents gui.h from replacing
 * WriteLogFile with a ((void)0) macro under NDEBUG, which would make this
 * function definition fail to compile.
 *
 * Log destination: %USERPROFILE%\Downloads\seraph.log
 * Format: [HH:MM:SS.mmm] message\r\n
 */

/* Include windows.h first.  The SERAPH_STUB_LOG_IMPL flag passed on the
 * compiler command-line ensures gui.h won't redefine WriteLogFile as a macro
 * before we get to define the real function. */
#include <windows.h>
#include <stdio.h>

static HANDLE           s_hLog   = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION s_logCs;
static volatile LONG    s_logInit = 0;

static void log_ensure_open(void) {
    if (InterlockedCompareExchange(&s_logInit, 1, 0) != 0) return;
    InitializeCriticalSection(&s_logCs);
    wchar_t path[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", path, MAX_PATH - 32);
    if (n == 0 || n >= MAX_PATH - 32)
        GetCurrentDirectoryW(MAX_PATH - 24, path);
    wcscat_s(path, MAX_PATH, L"\\Downloads\\seraph.log");
    s_hLog = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (s_hLog != INVALID_HANDLE_VALUE) {
        DWORD w;
        const char hdr[] = "\r\n=== Seraph session ===\r\n";
        WriteFile(s_hLog, hdr, (DWORD)(sizeof(hdr) - 1), &w, NULL);
    }
}

/* Internal write — no macro risk here since we haven't included any Loader hdr */
static void do_log(const char* msg) {
#ifndef NDEBUG
    if (!msg) return;
    log_ensure_open();
    if (s_hLog == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME t;
    GetLocalTime(&t);
    char line[512];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "[%02u:%02u:%02u.%03u] %s\r\n",
                        t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, msg);
    if (n <= 0) return;
    EnterCriticalSection(&s_logCs);
    DWORD w;
    WriteFile(s_hLog, line, (DWORD)n, &w, NULL);
    LeaveCriticalSection(&s_logCs);
#else
    (void)msg;
#endif
}

/* Public API — names match what every other .c extern-declares.
 * At this point in the TU, SERAPH_STUB_LOG_IMPL is defined so gui.h's
 * macro guard is inactive and these are plain function definitions. */
void WriteLog(const char* msg)     { do_log(msg); }

/* Attach_Invalidate — no-op in Stub.exe (driver lives in svc.dll).
 * The real implementation is in Loader/attach.c linked into svc.dll. */
void Attach_Invalidate(void) { /* no-op */ }
