#pragma once
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif

void ShowMainGUI(void);
void ShowMenuDirect(LPWSTR lC);
BOOL InitializeSeraphProduct(HWND hWnd);
void WriteLog(const char* msg);
/* WriteLogFile / WriteLogFileEx — real functions provided by debug_buffer.c.
 * Declared in debug_buffer.h, which is included via debug.h by every .c file.
 * The stub build (SERAPH_STUB_LOG_IMPL) provides its own implementation
 * in stub_log.c — the macros are NOT defined here to avoid shadowing the
 * real function declarations. */

#ifdef __cplusplus
}
#endif
