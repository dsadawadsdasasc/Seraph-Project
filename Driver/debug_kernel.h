/*
 * debug_kernel.h — Debug macros for kernel-mode code.
 *
 * D-DRV-1: Driver agora inclui este header em vez de "../Loader/debug.h".
 * O debug.h do Loader usa CreateFileA / lstrcatA e APIs de userland — inválidas
 * em kernel mode. Este header redireciona para DbgPrint (somente com _DEBUG).
 */
#pragma once

#ifdef _DEBUG
#  define DEBUG_PRINT(fmt, ...)    DbgPrint("[DRV] " fmt "\n", ##__VA_ARGS__)
#  define DEBUG_ERROR(fmt, ...)    DbgPrint("[DRV][ERR] " fmt "\n", ##__VA_ARGS__)
#  define DEBUG_NTSTATUS(msg, st)  DbgPrint("[DRV][ERR] " msg " NTSTATUS=0x%08X\n", (ULONG)(st))
#  define DEBUG_ENTER_FUNCTION()   DbgPrint("[DRV] >> %s\n", __FUNCTION__)
#  define DEBUG_EXIT_FUNCTION()    DbgPrint("[DRV] << %s\n", __FUNCTION__)
#  define DEBUG_PRINT_W(msg)       DbgPrint("[DRV] " msg "\n")
#  define DEBUG_PRINT_HEX(label, buf, len)  /* hex dump not implemented in kernel no-op */
#else
#  define DEBUG_PRINT(fmt, ...)    ((void)0)
#  define DEBUG_ERROR(fmt, ...)    ((void)0)
#  define DEBUG_NTSTATUS(msg, st)  ((void)0)
#  define DEBUG_ENTER_FUNCTION()   ((void)0)
#  define DEBUG_EXIT_FUNCTION()    ((void)0)
#  define DEBUG_PRINT_W(msg)       ((void)0)
#  define DEBUG_PRINT_HEX(l, b, n) ((void)0)
#endif

/* These macros are used in driver.c but not applicable in kernel — define as no-ops */
#define DEBUG_PATCH(fmt, ...)     DEBUG_PRINT(fmt, ##__VA_ARGS__)
#define DEBUG_PATCH_HEX(l, b, n) ((void)0)
#define DEBUG_HOOK(fmt, ...)      DEBUG_PRINT(fmt, ##__VA_ARGS__)
#define DEBUG_PIDB(fmt, ...)      DEBUG_PRINT(fmt, ##__VA_ARGS__)
#define DEBUG_PIIDCACHE(fmt, ...) DEBUG_PRINT(fmt, ##__VA_ARGS__)
