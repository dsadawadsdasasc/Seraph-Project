#include <windows.h>
#include <winternl.h>

extern "C" void ShowMainGUI(void);

static DWORD WINAPI CheatThread(LPVOID lpParam) {
    (void)lpParam;
    ShowMainGUI();
    return 0;
}

extern "C" __declspec(dllexport) HANDLE StartCheat(HINSTANCE hLoaderInstance) {
    return CreateThread(NULL, 0, CheatThread, (LPVOID)hLoaderInstance, 0, NULL);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────────
 *  Global system shims for features (aimbot.c, esp.c, local_player.c etc.)
 * ───────────────────────────────────────────────────────────────────────────── */
extern "C" {
    NTSTATUS SysNtQuerySystemInformation(
        ULONG  SystemInformationClass,
        PVOID  SystemInformation,
        ULONG  SystemInformationLength,
        PULONG ReturnLength)
    {
        typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
        static PFN_NtQuerySystemInformation fn = NULL;
        if (!fn) {
            HMODULE h = GetModuleHandleA("ntdll.dll");
            if (h) fn = (PFN_NtQuerySystemInformation)(void*)GetProcAddress(h, "NtQuerySystemInformation");
        }
        if (!fn) return (NTSTATUS)0xC0000001L;
        return fn(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }

    NTSTATUS SysNtQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG  ProcessInformationClass,
        PVOID  ProcessInformation,
        ULONG  ProcessInformationLength,
        PULONG ReturnLength)
    {
        typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static PFN_NtQueryInformationProcess fn = NULL;
        if (!fn) {
            HMODULE h = GetModuleHandleA("ntdll.dll");
            if (h) fn = (PFN_NtQueryInformationProcess)(void*)GetProcAddress(h, "NtQueryInformationProcess");
        }
        if (!fn) return (NTSTATUS)0xC0000001L;
        return fn(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
    }

    NTSTATUS SysNtOpenProcess(PHANDLE ph, ACCESS_MASK ac, POBJECT_ATTRIBUTES oa, void* cid) {
        typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, void*);
        static PFN_NtOpenProcess fn = NULL;
        if (!fn) {
            HMODULE h = GetModuleHandleA("ntdll.dll");
            if (h) fn = (PFN_NtOpenProcess)(void*)GetProcAddress(h, "NtOpenProcess");
        }
        if (!fn) return (NTSTATUS)0xC0000001L;
        return fn(ph, ac, oa, cid);
    }

    NTSTATUS SysNtClose(HANDLE h) {
        return CloseHandle(h) ? 0 : (NTSTATUS)0xC0000001L;
    }

    NTSTATUS SysNtLoadDriver(void*)   { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtUnloadDriver(void*) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtOpenFile(void*, ACCESS_MASK, void*, void*, ULONG, ULONG) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtDeviceIoControlFile(HANDLE, HANDLE, void*, void*, void*, ULONG, void*, ULONG, void*, ULONG) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtMapViewOfSection(HANDLE, HANDLE, void**, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtUnmapViewOfSection(HANDLE, void*) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtCreateSection(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG, HANDLE) { return (NTSTATUS)0xC0000001L; }
    NTSTATUS SysNtSetSystemInformation(ULONG, PVOID, ULONG) { return (NTSTATUS)0xC0000001L; }

    /* ── Global Seraph DLL shims for keyauth ────────────────────────────── */
    PVOID SeraphLoadDll(const WCHAR* dllName, PHANDLE phMod) {
        HMODULE h = LoadLibraryW(dllName);
        if (phMod) *phMod = h;
        return (PVOID)h;
    }

    PVOID SeraphGetProcAddress(PVOID hMod, const char* funcName) {
        return (PVOID)GetProcAddress((HMODULE)hMod, funcName);
    }

    void SeraphFreeDll(PVOID hMod) {
        if (hMod) FreeLibrary((HMODULE)hMod);
    }

    /* ── Global SysNt User/Memory shims ─────────────────────────────────── */
    UINT SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize) {
        return SendInput(cInputs, pInputs, cbSize);
    }

    SHORT SysNtUserGetAsyncKeyState(int vKey) {
        return GetAsyncKeyState(vKey);
    }

    NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
        (void)Alertable;
        if (DelayInterval) {
            LONGLONG ms = -DelayInterval->QuadPart / 10000;
            Sleep((DWORD)ms);
        }
        return 0;
    }

    NTSTATUS SysNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
        return TerminateProcess(ProcessHandle, (UINT)ExitStatus) ? 0 : (NTSTATUS)0xC0000001L;
    }

    NTSTATUS SysNtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
    {
        (void)ZeroBits;
        LPVOID addr = VirtualAllocEx(ProcessHandle, *BaseAddress, *RegionSize, AllocationType, Protect);
        if (!addr) return (NTSTATUS)0xC0000001L;
        *BaseAddress = addr;
        return 0;
    }

    NTSTATUS SysNtProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect)
    {
        return VirtualProtectEx(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, OldProtect) ? 0 : (NTSTATUS)0xC0000001L;
    }

    NTSTATUS SysNtFreeVirtualMemory(
        HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
    {
        return VirtualFreeEx(ProcessHandle, *BaseAddress, *RegionSize, FreeType) ? 0 : (NTSTATUS)0xC0000001L;
    }

    NTSTATUS SysNtDuplicateObject(
        HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
        PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
    {
        return DuplicateHandle(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                               TargetHandle, DesiredAccess, (BOOL)HandleAttributes, Options) ? 0 : (NTSTATUS)0xC0000001L;
    }

    /* ── Global Seraph Heap and Thread shims ────────────────────────────── */
    PVOID SeraphHeapAlloc(SIZE_T size) {
        return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    }

    void SeraphHeapFree(PVOID ptr) {
        if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
    }

    HANDLE SeraphCreateThread(LPTHREAD_START_ROUTINE lpStartAddr, LPVOID lpParam) {
        return CreateThread(NULL, 0, lpStartAddr, lpParam, 0, NULL);
    }
}
