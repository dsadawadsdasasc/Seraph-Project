#pragma once
#include <Windows.h>
#include "shared.h"
#ifdef __cplusplus
extern "C" {
#endif
VOID UeInitializeEvasion(PEVASION_CONTEXT);
BOOLEAN CheckSandbox(void);
BOOLEAN CheckDebugger(void);
BOOLEAN CheckHardwareBreakpoints(void);
BOOLEAN CheckNtGlobalFlag(void);
PVOID UeAllocateStealthMemory(SIZE_T);
VOID UeProtectMemory(PVOID,SIZE_T,DWORD);
VOID UeFreeStealthMemory(PVOID);
VOID UeDelayExecution(PEVASION_CONTEXT);
// Process utilities
DWORD GetProcessIdByName(const WCHAR* processName);
PVOID GetProcessBaseAddress(DWORD pid);
PVOID GetDestiny2BaseAddress(void);
VOID UeErasePEHeader(void);
#ifdef __cplusplus
}
#endif
