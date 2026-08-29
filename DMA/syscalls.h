/*
 * syscalls.h  --  DMA build: redirect direct syscalls to standard ntdll API.
 *
 * Shadows Loader/syscalls.h + syscalls.c + syscalls_asm.asm.
 *
 * In the BYOVD build, these are direct syscall stubs (bypassing hooks) so
 * BattleEye cannot intercept the calls.  In the DMA build, the cheat runs
 * on the OPERATOR's machine — there is no BattleEye in our process space.
 * Regular ntdll calls are perfectly fine; the direct-syscall overhead is
 * unnecessary.
 *
 * Only SysNtQuerySystemInformation and SysNtQueryInformationProcess are
 * called by evasion_user.c.  The BYOVD-specific syscalls (NtLoadDriver,
 * NtDeviceIoControlFile, NtMapViewOfSection, etc.) are stubbed as no-ops
 * since no code in the DMA build calls them.
 */
#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Syscall number init — no-op for DMA (uses API, not raw syscalls) ───── */
static __inline void InitSyscallNumbers(void) { (void)0; }

/* ── Type shim for NtQuerySystemInformation ─────────────────────────────── */
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static __inline NTSTATUS SysNtQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength)
{
    static PFN_NtQuerySystemInformation fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) fn = (PFN_NtQuerySystemInformation)(void*)
                    GetProcAddress(h, "NtQuerySystemInformation");
    }
    if (!fn) return (NTSTATUS)0xC0000001L; /* STATUS_UNSUCCESSFUL */
    return fn(SystemInformationClass, SystemInformation,
              SystemInformationLength, ReturnLength);
}

static __inline NTSTATUS SysNtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength)
{
    static PFN_NtQueryInformationProcess fn = NULL;
    if (!fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) fn = (PFN_NtQueryInformationProcess)(void*)
                    GetProcAddress(h, "NtQueryInformationProcess");
    }
    if (!fn) return (NTSTATUS)0xC0000001L;
    return fn(ProcessHandle, ProcessInformationClass,
              ProcessInformation, ProcessInformationLength, ReturnLength);
}

/* ── BYOVD-only syscalls — no-ops in DMA build ──────────────────────────── */
static __inline NTSTATUS SysNtLoadDriver(void* /*DriverServiceName*/)
    { return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtUnloadDriver(void* /*DriverServiceName*/)
    { return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtOpenProcess(
    PHANDLE ph, ACCESS_MASK ac, POBJECT_ATTRIBUTES oa, void* cid)
{
    /* Use standard API on DMA machine — no stealth requirement */
    (void)ac; (void)oa;
    typedef NTSTATUS (NTAPI *PFN)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,void*);
    static PFN fn = NULL;
    if (!fn) { HMODULE h = GetModuleHandleA("ntdll.dll");
               if (h) fn = (PFN)(void*)GetProcAddress(h, "NtOpenProcess"); }
    if (!fn || !ph) return (NTSTATUS)0xC0000001L;
    return fn(ph, ac, oa, cid);
}

static __inline NTSTATUS SysNtOpenFile(
    void* fh, ACCESS_MASK ac, void* oa, void* io, ULONG sh, ULONG opt)
    { (void)fh;(void)ac;(void)oa;(void)io;(void)sh;(void)opt;
      return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtDeviceIoControlFile(
    HANDLE fh, HANDLE ev, void* ar, void* ac, void* io, ULONG cc,
    void* ib, ULONG il, void* ob, ULONG ol)
    { (void)fh;(void)ev;(void)ar;(void)ac;(void)io;(void)cc;
      (void)ib;(void)il;(void)ob;(void)ol; return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtClose(HANDLE h)
    { return CloseHandle(h) ? 0 : (NTSTATUS)0xC0000001L; }

/* Remaining BYOVD syscall stubs (NtMapViewOfSection, etc.) */
static __inline NTSTATUS SysNtMapViewOfSection(
    HANDLE sh, HANDLE ph, void** ba, ULONG_PTR zb, SIZE_T cs,
    PLARGE_INTEGER so, PSIZE_T vs, ULONG iha, ULONG at, ULONG pp)
    { (void)sh;(void)ph;(void)ba;(void)zb;(void)cs;(void)so;
      (void)vs;(void)iha;(void)at;(void)pp; return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtUnmapViewOfSection(HANDLE ph, void* ba)
    { return UnmapViewOfFile(ba) ? 0 : (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtCreateSection(
    PHANDLE sh, ACCESS_MASK ac, void* oa, PLARGE_INTEGER ms,
    ULONG pp, ULONG ao, HANDLE fh)
    { (void)sh;(void)ac;(void)oa;(void)ms;(void)pp;(void)ao;(void)fh;
      return (NTSTATUS)0xC0000001L; }

static __inline NTSTATUS SysNtSetSystemInformation(
    ULONG sic, PVOID si, ULONG sil)
    { (void)sic;(void)si;(void)sil; return (NTSTATUS)0xC0000001L; }

/* ── Inline shims for other Syscall functions ───────────────────────────── */
static __inline NTSTATUS SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize) {
    return SendInput(cInputs, pInputs, cbSize) ? 0 : (NTSTATUS)0xC0000001L;
}

static __inline SHORT SysNtUserGetAsyncKeyState(int vKey) {
    return GetAsyncKeyState(vKey);
}

static __inline NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    (void)Alertable;
    if (DelayInterval) {
        // DelayInterval is in 100ns units, negative for relative time
        LONGLONG ms = -DelayInterval->QuadPart / 10000;
        Sleep((DWORD)ms);
    }
    return 0;
}

static __inline NTSTATUS SysNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    return TerminateProcess(ProcessHandle, (UINT)ExitStatus) ? 0 : (NTSTATUS)0xC0000001L;
}

static __inline NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    (void)ZeroBits;
    LPVOID addr = VirtualAllocEx(ProcessHandle, *BaseAddress, *RegionSize, AllocationType, Protect);
    if (!addr) return (NTSTATUS)0xC0000001L;
    *BaseAddress = addr;
    return 0;
}

static __inline NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    return VirtualProtectEx(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, OldProtect) ? 0 : (NTSTATUS)0xC0000001L;
}

static __inline NTSTATUS SysNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return VirtualFreeEx(ProcessHandle, *BaseAddress, *RegionSize, FreeType) ? 0 : (NTSTATUS)0xC0000001L;
}

static __inline NTSTATUS SysNtDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
    PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    return DuplicateHandle(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                           TargetHandle, DesiredAccess, (BOOL)HandleAttributes, Options) ? 0 : (NTSTATUS)0xC0000001L;
}

/* ── Inline shims for Seraph memory and threading wrappers ───────────────── */
static __inline PVOID SeraphHeapAlloc(SIZE_T size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static __inline void SeraphHeapFree(PVOID ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

static __inline HANDLE SeraphCreateThread(LPTHREAD_START_ROUTINE lpStartAddr, LPVOID lpParam) {
    return CreateThread(NULL, 0, lpStartAddr, lpParam, 0, NULL);
}

/* Declarations for keyauth.obj extern references */
PVOID SeraphLoadDll(const WCHAR* dllName, PHANDLE phMod);
PVOID SeraphGetProcAddress(PVOID hMod, const char* funcName);
void SeraphFreeDll(PVOID hMod);

#ifdef __cplusplus
}
#endif
