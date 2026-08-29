#pragma once
#include <Windows.h>
#include <winternl.h>

/* CLIENT_ID is already defined by winternl.h */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Pseudo-handles — avoids GetCurrentProcess/GetCurrentThread import */
#define SERAPH_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#define SERAPH_CURRENT_THREAD  ((HANDLE)(LONG_PTR)-2)

/* ========================================================================
 * ntoskrnl syscalls (existing)
 * ======================================================================== */

NTSTATUS SysNtLoadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS SysNtUnloadDriver(PUNICODE_STRING DriverServiceName);
NTSTATUS SysNtQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);
NTSTATUS SysNtOpenProcess(
    PHANDLE             ProcessHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    CLIENT_ID*          ClientId
);
NTSTATUS SysNtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);
NTSTATUS SysNtClose(HANDLE Handle);
NTSTATUS SysNtOpenFile(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions
);
NTSTATUS SysNtDeviceIoControlFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
);
NTSTATUS SysNtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);
NTSTATUS SysNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS SysNtDuplicateObject(
    HANDLE      SourceProcessHandle,
    HANDLE      SourceHandle,
    HANDLE      TargetProcessHandle,
    PHANDLE     TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Options
);
NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);

/* ========================================================================
 * ntoskrnl syscalls (new — Phase 1)
 * ======================================================================== */

/* Replaces CreateThread/kernel32. Use SeraphCreateThread() for convenience. */
NTSTATUS SysNtCreateThreadEx(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       StartRoutine,
    PVOID       Argument,
    ULONG       CreateFlags,
    SIZE_T      ZeroBits,
    SIZE_T      StackSize,
    SIZE_T      MaximumStackSize,
    PVOID       AttributeList
);

/* Replaces VirtualAlloc. Use SeraphVAlloc() for convenience. */
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

/* Replaces VirtualProtect. Use SeraphVProtect() for convenience. */
NTSTATUS SysNtProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

/* Replaces VirtualFree. Use SeraphVFree() for convenience. */
NTSTATUS SysNtFreeVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

/* Replaces Sleep / SleepEx. Use SeraphSleep() for convenience. */
NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

/* Replaces TerminateProcess */
NTSTATUS SysNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSTATUS SysNtOpenProcessToken(
    HANDLE      ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE     TokenHandle
);

NTSTATUS SysNtAdjustPrivilegesToken(
    HANDLE            TokenHandle,
    BOOLEAN           DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG             BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG            ReturnLength
);

/* ========================================================================
 * win32k syscalls (extracted from win32u.dll — SSN range 0x1000+)
 * ======================================================================== */

/* Replaces SendInput (user32 → win32k).
 * NOTE: Same binary signature as SendInput — drop-in replacement. */
UINT SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize);

/* Replaces GetAsyncKeyState (user32 → win32k).
 * Returns SHORT with same bit layout as GetAsyncKeyState. */
SHORT SysNtUserGetAsyncKeyState(int vKey);

/* ========================================================================
 * High-level inline helpers (use these instead of Win32 wrappers)
 * ======================================================================== */

/* SeraphSleep — replaces Sleep(ms). Zero kernel32 involvement. */
static __inline void SeraphSleep(DWORD ms) {
    LARGE_INTEGER d;
    d.QuadPart = -((LONGLONG)ms * 10000LL);
    SysNtDelayExecution(FALSE, &d);
}

/* SeraphVAlloc — replaces VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, protect) */
static __inline PVOID SeraphVAlloc(SIZE_T size, ULONG protect) {
    PVOID  base = NULL;
    SIZE_T sz   = size;
    SysNtAllocateVirtualMemory(SERAPH_CURRENT_PROCESS, &base, 0, &sz,
                               MEM_COMMIT | MEM_RESERVE, protect);
    return base;
}

/* SeraphVFree — replaces VirtualFree(p, 0, MEM_RELEASE) */
static __inline void SeraphVFree(PVOID p) {
    SIZE_T sz = 0;
    SysNtFreeVirtualMemory(SERAPH_CURRENT_PROCESS, &p, &sz, MEM_RELEASE);
}

/* SeraphVProtect — replaces VirtualProtect(p, size, newProt, &old).
 * Returns TRUE on success; fills *oldProt with previous protection. */
static __inline BOOL SeraphVProtect(PVOID p, SIZE_T size, ULONG newProt, PULONG oldProt) {
    ULONG    old = 0;
    NTSTATUS st  = SysNtProtectVirtualMemory(SERAPH_CURRENT_PROCESS, &p, &size, newProt, &old);
    if (oldProt) *oldProt = old;
    return NT_SUCCESS(st);
}

/* SeraphCreateThread — replaces CreateThread via ntdll!RtlCreateUserThread.
 * - Zero SSN extraction: resolves RtlCreateUserThread by EAT hash walk.
 * - Zero kernel32: ntdll only. Thread proc can safely return.
 * - Implemented in syscalls.c (pre-resolves at InitSyscallNumbers time).
 * Returns HANDLE on success, NULL on failure. Close with SysNtClose(). */
HANDLE SeraphCreateThread(PVOID startRoutine, PVOID arg);

/* SeraphHeapAlloc — replaces HeapAlloc(GetProcessHeap(), 0, size).
 * Uses RtlAllocateHeap from ntdll EAT hash walk + PEB->ProcessHeap.
 * SUPERIOR to HeapAlloc: no IAT import, no kernel32, no new VAD entry. */
PVOID SeraphHeapAlloc(SIZE_T size);

/* SeraphHeapFree — replaces HeapFree(GetProcessHeap(), 0, p).
 * Uses RtlFreeHeap from ntdll EAT hash walk. */
BOOL SeraphHeapFree(PVOID p);

/* SeraphHeapAllocZero — like SeraphHeapAlloc but zeroes memory (HEAP_ZERO_MEMORY). */
PVOID SeraphHeapAllocZero(SIZE_T size);

/* SeraphLoadDll — replaces LoadLibraryW via LdrLoadDll (ntdll export).
 * Returns module DllBase on success, NULL on failure.
 * *phMod receives the HMODULE (same as DllBase on Windows). */
PVOID SeraphLoadDll(const WCHAR* dllName, PHANDLE phMod);

/* SeraphFreeDll — replaces FreeLibrary via LdrUnloadDll (ntdll export). */
BOOL SeraphFreeDll(HANDLE hMod);

/* SeraphGetProcAddress — replaces GetProcAddress via EAT parsing in memory.
 * Resolves function names directly from HMODULE export directory. */
PVOID SeraphGetProcAddress(HANDLE hModule, const char* name);

/* Initialize syscall numbers — MUST be called once before any Sys* function. */
BOOL InitSyscallNumbers(void);

#ifdef __cplusplus
}
#endif