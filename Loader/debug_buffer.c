/*
 * debug_buffer.c — Deferred logging ring buffer implementation.
 *
 * 512KB circular buffer in heap. Messages are appended atomically.
 * On error -> entire history is flushed to seraph_crash.txt.
 * On normal exit -> buffer is freed, no files created.
 */

#include "debug_buffer.h"
#include <stdio.h>
#include <string.h>
#include "syscalls.h"  /* SeraphHeapAlloc, SeraphHeapFree, SysNtClose */

#define LOG_BUFFER_SIZE  (512 * 1024)  /* 512KB ring buffer */

static char*         g_buf      = NULL;
static volatile LONG g_pos      = 0;
static volatile LONG g_wrapped  = 0;  /* 1 if buffer has wrapped around */
static volatile LONG g_inited   = 0;
static volatile LONG g_flushed  = 0;  /* prevent double-flush */
static CRITICAL_SECTION g_cs;

void DbgBuf_Init(void) {
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0) return;
    InitializeCriticalSection(&g_cs);
    g_buf = (char*)SeraphHeapAlloc(LOG_BUFFER_SIZE);
    if (g_buf) memset(g_buf, 0, LOG_BUFFER_SIZE);
    g_pos = 0;
    g_wrapped = 0;
    g_flushed = 0;
}

BOOL DbgBuf_IsReady(void) {
    return (g_inited && g_buf != NULL);
}

void DbgBuf_Write(const char* msg) {
    if (!g_buf || !msg) return;

    int len = (int)strlen(msg);
    if (len <= 0) return;
    /* Cap individual message to 2KB to prevent one huge message from corrupting buffer */
    if (len > 2048) len = 2048;

    EnterCriticalSection(&g_cs);

    LONG pos = g_pos;
    if (pos + len >= LOG_BUFFER_SIZE) {
        /* Wrap around */
        g_wrapped = 1;
        pos = 0;
    }
    for (size_t _i = 0; _i < len; _i++) g_buf[pos + _i] = msg[_i];
    g_pos = pos + len;

    LeaveCriticalSection(&g_cs);

}

void DbgBuf_Flush(const char* filename) {
#ifdef NDEBUG
    /* Release builds never write log files to disk. */
    (void)filename;
    return;
#else
    if (!g_buf) return;
    /* Prevent multiple flushes from concurrent error paths */
    if (InterlockedCompareExchange(&g_flushed, 1, 0) != 0) return;

    const char* fname = filename ? filename : "svc_err.log";

    EnterCriticalSection(&g_cs);

    HANDLE hFile = CreateFileA(fname, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        /* Write header */
        const char header[] = "=== DEFERRED LOG DUMP ===\r\n"
                              "Error triggered log flush.\r\n"
                              "===================================\r\n\r\n";
        WriteFile(hFile, header, (DWORD)strlen(header), &written, NULL);

        if (g_wrapped) {
            /* Buffer wrapped: write from g_pos to end, then from 0 to g_pos */
            LONG pos = g_pos;
            LONG remaining = LOG_BUFFER_SIZE - pos;
            /* Find the start of the next valid message after pos (skip partial) */
            LONG start = pos;
            while (start < LOG_BUFFER_SIZE && g_buf[start] != '[' && g_buf[start] != '\0') start++;
            if (start < LOG_BUFFER_SIZE && g_buf[start] != '\0')
                WriteFile(hFile, g_buf + start, LOG_BUFFER_SIZE - start, &written, NULL);
            /* Then the newer part: 0..pos */
            if (pos > 0)
                WriteFile(hFile, g_buf, pos, &written, NULL);
        } else {
            /* No wrap: write 0..g_pos */
            if (g_pos > 0)
                WriteFile(hFile, g_buf, g_pos, &written, NULL);
        }
        SysNtClose(hFile);
    }

    LeaveCriticalSection(&g_cs);
#endif
}

void DbgBuf_Free(void) {
    if (g_buf) {
#ifndef NDEBUG
        /* Em debug builds (b_debug.bat), salva o log de sessão em svc_session.log no exit */
        InterlockedExchange(&g_flushed, 0);
        DbgBuf_Flush("svc_session.log");
#endif
        SecureZeroMemory(g_buf, LOG_BUFFER_SIZE);
        SeraphHeapFree(g_buf);
        g_buf = NULL;
    }
    if (g_inited) {
        DeleteCriticalSection(&g_cs);
        g_inited = 0;
    }
}

/* ─── Per-module log file writer ─────────────────────────────────────────── */

static CRITICAL_SECTION g_file_cs;
static volatile LONG g_file_cs_init = 0;

static void file_cs_ensure(void) {
    if (InterlockedCompareExchange(&g_file_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_file_cs);
}

void WriteLogFileEx(const char* filename, const char* msg) {
    if (!filename || !msg || !*filename || !*msg) return;
#ifdef NDEBUG
    /* Em release builds, redireciona logs exclusivamente para o ring buffer em RAM.
     * Nenhum arquivo fisico e criado em disco durante a execucao normal. */
    DbgBuf_Write(msg);
    return;
#else
    file_cs_ensure();

    EnterCriticalSection(&g_file_cs);

    /* Build timestamp prefix: [HH:MM:SS.mmm] */
    char tbuf[32];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(tbuf, sizeof(tbuf), "[%02d:%02d:%02d.%03d] ",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    HANDLE hFile = INVALID_HANDLE_VALUE;
    char logPath[MAX_PATH];
    if (GetModuleFileNameA(NULL, logPath, MAX_PATH)) {
        char* lastSlash = strrchr(logPath, '\\');
        if (lastSlash) {
            *(lastSlash + 1) = '\0';
            strncat(logPath, filename, sizeof(logPath) - strlen(logPath) - 1);
        } else {
            strncpy(logPath, filename, sizeof(logPath) - 1);
        }
        hFile = CreateFileA(logPath, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    } else {
        hFile = CreateFileA(filename, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, tbuf, (DWORD)strlen(tbuf), &written, NULL);
        DWORD msglen = (DWORD)strlen(msg);
        WriteFile(hFile, msg, msglen, &written, NULL);
        const char crlf[] = "\r\n";
        WriteFile(hFile, crlf, 2, &written, NULL);
        SysNtClose(hFile);
    }

    LeaveCriticalSection(&g_file_cs);
#endif
}

void WriteLogFile(const char* msg) {
    WriteLogFileEx("seraph_debug.log", msg);
}
