/*
 * dma_dll_loader.h — Extract and load MemProcFS DLLs from embedded RCDATA.
 * Standalone EXE: vmm.dll + leechcore.dll + FTD3XX.dll (IDs 401–403).
 */
#pragma once
#include <windows.h>
#include "Resource.h"

#ifdef __cplusplus
extern "C" {
#endif

extern wchar_t g_dmaExtractDir[MAX_PATH];
extern wchar_t g_vmmDllPath    [MAX_PATH];
extern wchar_t g_leechDllPath  [MAX_PATH];
extern wchar_t g_ftdDllPath    [MAX_PATH];

/* Extract + DLL search path + LoadLibrary (full paths). Call before ShowMainGUI. */
BOOL DmaLoader_Init(HMODULE hModule);
DWORD DmaLoader_GetLastError(void);

/* Re-apply search path before VMMDLL_Initialize (safe to call often). */
void DmaLoader_EnsureSearchPath(void);

void DmaLoader_Cleanup(void);

#ifdef __cplusplus
}
#endif
