
/*
 * syscalls.c -- Syscall number extraction for Seraph Loader (Phase 1 expansion)
 *
 * The actual syscall stubs (mov r10,rcx / mov eax,[num] / jmp gadget)
 * are in syscalls_asm.asm (assembled by ml64.exe).
 * This file extracts syscall numbers from ntdll (ntoskrnl) and win32u.dll
 * (win32k) at runtime and stores them in globals that the ASM stubs read.
 *
 * All globals MUST be non-static so the EXTERN declarations in .asm resolve.
 *
 * Key design points:
 *   P5.1  — indirect syscall via ntdll gadget (RIP appears in ntdll on stack walk)
 *   P5.2  — EAT hash walk replaces GetProcAddress
 *   Phase1 — PEB walk (_FindModuleBase) replaces GetModuleHandleW for ntdll/win32u
 */

#include "syscalls.h"
#include "debug.h"
#include "ThemidaSDK.h"
#include "XorStr.h"
#include "xor_strings.h"
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

/* ── P5.1: VA of `syscall; ret` gadget inside ntdll.dll ──────────────────── */
ULONGLONG g_SyscallGadgetVA = 0;

/* ── Existing ntoskrnl syscall number cache ───────────────────────────────── */
DWORD g_NtLoadDriverSyscall              = 0;
DWORD g_NtUnloadDriverSyscall            = 0;
DWORD g_NtQuerySystemInformationSyscall  = 0;
DWORD g_NtOpenProcessSyscall             = 0;
DWORD g_NtQueryInformationProcessSyscall = 0;
DWORD g_SysNtOpenFileSyscall             = 0;
DWORD g_SysNtDeviceIoControlFileSyscall  = 0;
DWORD g_SysNtCloseSyscall                = 0;
DWORD g_SysNtMapViewOfSectionSyscall     = 0;
DWORD g_SysNtUnmapViewOfSectionSyscall   = 0;
DWORD g_SysNtDuplicateObjectSyscall      = 0;
DWORD g_SysNtGetContextThreadSyscall     = 0;
/* NOTE: SysNtReadVirtualMemory intentionally absent — use BYOVD_ReadVA. */

/* ── New ntoskrnl syscall numbers (Phase 1) ──────────────────────────────── */
DWORD g_SysNtCreateThreadExSyscall        = 0;
DWORD g_SysNtAllocateVirtualMemorySyscall = 0;
DWORD g_SysNtProtectVirtualMemorySyscall  = 0;
DWORD g_SysNtFreeVirtualMemorySyscall     = 0;
DWORD g_SysNtDelayExecutionSyscall        = 0;
DWORD g_SysNtTerminateProcessSyscall      = 0;
DWORD g_SysNtOpenProcessTokenSyscall      = 0;
DWORD g_SysNtAdjustPrivilegesTokenSyscall = 0;


/* ── win32k syscall numbers — extracted from win32u.dll (Phase 1) ─────────── */
DWORD g_SysNtUserSendInputSyscall        = 0;
DWORD g_SysNtUserGetAsyncKeyStateSyscall = 0;

/* ==========================================================================
 * P5.2 / Phase1: Internal helpers — no Win32 API involvement
 * ========================================================================== */

/* SeraphHash32: custom 32-bit hash for EAT name matching.
 * Distinct from FNV-1a to break YARA rules targeting 0x811C9DC5/0x01000193. */
static DWORD SeraphHash32(const char* s) {
    DWORD h = 0xA3C59F17u;
    for (; *s; s++) { h ^= (BYTE)*s; h = (h << 5) | (h >> 27); h *= 0x27D4EB2Fu; }
    return h;
}

/* SeraphHash32W: wide-char variant, case-insensitive (for module name lookup). */
static DWORD SeraphHash32W(const WCHAR* s) {
    DWORD h = 0xA3C59F17u;
    for (; *s; s++) {
        WCHAR c = *s;
        if (c >= L'A' && c <= L'Z') c += 32; /* toLower */
        h ^= (BYTE)(c & 0xFF);
        h = (h << 5) | (h >> 27);
        h *= 0x27D4EB2Fu;
    }
    return h;
}

/* _FindModuleBase: walks PEB.Ldr.InLoadOrderModuleList to find a module DllBase.
 * Replaces GetModuleHandleW — zero Win32 API calls.
 *
 * LDR_DATA_TABLE_ENTRY x64 offsets (Win10/11):
 *   +0x000 InLoadOrderLinks (LIST_ENTRY, 16 bytes)
 *   +0x030 DllBase          (PVOID, 8 bytes)
 *   +0x058 BaseDllName      (UNICODE_STRING: Length@+0x58, Buffer@+0x60)
 */
static BYTE* _FindModuleBase(const WCHAR* targetName) {
    DWORD targetHash = SeraphHash32W(targetName);
    PPEB  peb = (PPEB)__readgsqword(0x60);
    if (!peb) return NULL;
    /* PEB_LDR_DATA on x64:
     *   +0x00 Length (ULONG)
     *   +0x04 Initialized (BOOLEAN)
     *   +0x08 SsHandle (PVOID)
     *   +0x10 InLoadOrderModuleList (LIST_ENTRY)
     * winternl.h hides InLoadOrderModuleList — use offset directly. */
    BYTE* ldr = *(BYTE**)((BYTE*)peb + 0x18); /* PEB->Ldr at PEB+0x18 on x64 */
    if (!ldr) return NULL;
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10); /* Ldr->InLoadOrderModuleList at +0x10 */
    LIST_ENTRY* curr = head->Flink;
    while (curr && curr != head) {
        USHORT nameLen = *(USHORT*)((BYTE*)curr + 0x58);  /* BaseDllName.Length */
        PWCHAR nameBuf = *(PWCHAR*) ((BYTE*)curr + 0x60); /* BaseDllName.Buffer */
        PVOID  dllBase = *(PVOID*)  ((BYTE*)curr + 0x30); /* DllBase */
        if (nameBuf && nameLen > 0 && dllBase) {
            DWORD h = 0xA3C59F17u;
            for (USHORT i = 0; i < nameLen / 2; i++) {
                WCHAR c = nameBuf[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                h ^= (BYTE)(c & 0xFF);
                h = (h << 5) | (h >> 27);
                h *= 0x27D4EB2Fu;
            }
            if (h == targetHash) return (BYTE*)dllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

/* _WalkEAT: generic EAT hash resolver for any DLL base.
 * Replaces GetProcAddress — no Win32 API calls. */
static BYTE* _WalkEAT(BYTE* base, DWORD nameHash) {
    if (!base) return NULL;
    IMAGE_DOS_HEADER*   dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64* nt  = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY* expDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir->VirtualAddress || expDir->Size == 0) return NULL;

    DWORD expRVA = expDir->VirtualAddress;
    DWORD expSize = expDir->Size;
    DWORD dllSize = nt->OptionalHeader.SizeOfImage;

    /* Verify the export directory is within the image bounds */
    if (expRVA >= dllSize) return NULL;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expRVA);

    /* Validate table RVAs */
    if (exp->AddressOfNames >= dllSize || 
        exp->AddressOfFunctions >= dllSize || 
        exp->AddressOfNameOrdinals >= dllSize) {
        return NULL;
    }

    DWORD* names    = (DWORD*)(base + exp->AddressOfNames);
    DWORD* funcs    = (DWORD*)(base + exp->AddressOfFunctions);
    WORD*  ordinals = (WORD*) (base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (names[i] == 0 || names[i] >= dllSize) continue;
        const char* nm = (const char*)(base + names[i]);
        if (SeraphHash32(nm) == nameHash) {
            DWORD funcRVA = funcs[ordinals[i]];
            if (funcRVA == 0 || funcRVA >= dllSize) return NULL;

            /* Check for Forwarded Exports (falls inside the export directory) */
            if (funcRVA >= expRVA && funcRVA < (expRVA + expSize)) {
                return NULL;
            }
            return base + funcRVA;
        }
    }
    return NULL;
}

/* ResolveNtdllExportByHash: EAT walk on ntdll.dll — replaces GetModuleHandleW+GetProcAddress. */
static BYTE* ResolveNtdllExportByHash(DWORD nameHash) {
    BYTE* base = _FindModuleBase(DXOR_W(ENC_ntdll_dll));
    return _WalkEAT(base, nameHash);
}

/* ResolveWin32uExportByHash: EAT walk on win32u.dll (win32k usermode thunks).
 * "win32u.dll" XOR-encoded with key 0x3F — no literal in .rdata. */
static BYTE* ResolveWin32uExportByHash(DWORD nameHash) {
    /* 0x48 0x56 0x51 0x0C 0x0D 0x4A 0x11 0x5B 0x53 0x53 ^ 0x3F = "win32u.dll" */
    static const unsigned char _e[] = {0x48,0x56,0x51,0x0C,0x0D,0x4A,0x11,0x5B,0x53,0x53,0x00};
    WCHAR _w[11];
    for (int _i = 0; _i < 10; _i++) _w[_i] = (WCHAR)(((unsigned char)_e[_i]) ^ 0x3F);
    _w[10] = 0;
    BYTE* base = _FindModuleBase(_w);
    return _WalkEAT(base, nameHash);
}

/* ResolveUser32ExportByHash: EAT walk on user32.dll for direct input APIs.
 * "user32.dll" XOR-encoded with key 0x4D — no literal in .rdata. */
static BYTE* ResolveUser32ExportByHash(DWORD nameHash) {
    static const unsigned char _e[] = {0x38,0x3E,0x28,0x3F,0x7E,0x7F,0x63,0x29,0x21,0x21,0x00};
    WCHAR _w[11];
    for (int _i = 0; _i < 10; _i++) _w[_i] = (WCHAR)(((unsigned char)_e[_i]) ^ 0x4D);
    _w[10] = 0;
    BYTE* base = _FindModuleBase(_w);
    return _WalkEAT(base, nameHash);
}

typedef SHORT (WINAPI* _tGetAsyncKeyState_fb)(int);
typedef UINT  (WINAPI* _tSendInput_fb)(UINT, LPINPUT, int);
static _tGetAsyncKeyState_fb s_pfnGetAsyncKeyState_fb = NULL;
static _tSendInput_fb        s_pfnSendInput_fb        = NULL;


/* FindSyscallGadgetVA: locate `syscall; ret` (0F 05 C3) inside an ntdll stub.
 * Uses ResolveNtdllExportByHash — no GetModuleHandleW, no GetProcAddress. */
static ULONGLONG FindSyscallGadgetVA(void) {
    BYTE* p = ResolveNtdllExportByHash(SeraphHash32(DXOR_A(ENC_NtClose)));
    if (!p) return 0;
    for (int i = 0; i < 62; i++) {  /* 62 = 64-2: ensure i+2 stays in window */
        if (p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3)
            return (ULONGLONG)(p + i);
    }
    return 0;
}

/* _SanitiseSyscallNum: validate ntoskrnl SSN is in plausible range (1–0xFFF). */
static DWORD _SanitiseSyscallNum(DWORD n, LPCSTR fn) {
    if (n == 0 || n >= 0x1000) {
        DEBUG_SYSCALL("ExtractSyscallNumber: implausible num=0x%X for %s", n, fn);
        return 0;
    }
    return n;
}

/* _SanitiseSyscallNumW32k: validate win32k SSN is in range 0x1000–0x2FFF. */
static DWORD _SanitiseSyscallNumW32k(DWORD n, LPCSTR fn) {
    if (n < 0x1000 || n >= 0x3000) {
        DEBUG_SYSCALL("ExtractWin32kSyscallNumber: implausible num=0x%X for %s", n, fn);
        return 0;
    }
    return n;
}

/* Forward declarations for heap helpers used in InitSyscallNumbersImpl (pre-resolution). */
typedef PVOID (NTAPI* _tRtlAllocateHeap)(PVOID, ULONG, SIZE_T);
typedef BOOL  (NTAPI* _tRtlFreeHeap)    (PVOID, ULONG, PVOID);
static _tRtlAllocateHeap s_pfnRtlAllocateHeap = NULL;
static _tRtlFreeHeap     s_pfnRtlFreeHeap     = NULL;

/* RtlCreateUserThread — used by SeraphCreateThread instead of NtCreateThreadEx.
 * This is an ntdll EXPORT (no SSN needed), so resolution is via EAT hash walk.
 * Signature on x64 Win10/11 (10 params): */
typedef NTSTATUS (NTAPI* _tRtlCreateUserThread)(
    HANDLE   ProcessHandle,
    PVOID    SecurityDescriptor,
    BOOLEAN  CreateSuspended,
    ULONG    StackZeroBits,
    PSIZE_T  StackReserve,
    PSIZE_T  StackCommit,
    PVOID    StartAddress,
    PVOID    StartParameter,
    PHANDLE  ThreadHandle,
    PVOID    ClientId
);
static _tRtlCreateUserThread s_pfnRtlCreateUserThread = NULL;

/* ExtractSyscallNumberImpl: parse SSN from ntdll stub byte pattern.
 * Now resolves via hash walk — no GetProcAddress. */
static __declspec(noinline) DWORD ExtractSyscallNumberImpl(LPCSTR functionName) {
    DWORD _esn_result = 0;
    BYTE* bytes = ResolveNtdllExportByHash(SeraphHash32(functionName));
    if (!bytes) goto _esn_end;
    for (int i = 0; i < 64 - 8; i++) {
        /* Pattern 1: 4C 8B D1 B8 [SSN] — standard Win10 stub */
        if (bytes[i]==0x4C && bytes[i+1]==0x8B && bytes[i+2]==0xD1 && bytes[i+3]==0xB8) {
            _esn_result = _SanitiseSyscallNum(*(DWORD*)(bytes + i + 4), functionName);
            goto _esn_end;
        }
        /* Pattern 2: 49 8B D2 B8 [SSN] — alternate stub */
        if (bytes[i]==0x49 && bytes[i+1]==0x8B && bytes[i+2]==0xD2 && bytes[i+3]==0xB8) {
            _esn_result = _SanitiseSyscallNum(*(DWORD*)(bytes + i + 4), functionName);
            goto _esn_end;
        }
        /* Pattern 3: B8 [SSN] 0F 05 — short stub (some Win11 builds) */
        if (bytes[i]==0xB8 && i<16 && bytes[i+5]==0x0F && bytes[i+6]==0x05) {
            _esn_result = _SanitiseSyscallNum(*(DWORD*)(bytes + i + 1), functionName);
            goto _esn_end;
        }
    }
    /* Fallback: find first B8 (MOV EAX, imm32) within first 32 bytes */
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) {
            _esn_result = _SanitiseSyscallNum(*(DWORD*)(bytes + i + 1), functionName);
            goto _esn_end;
        }
    }
    DEBUG_SYSCALL("ExtractSyscallNumber: pattern not found for %s", functionName);
_esn_end:
    return _esn_result;
}

/* ExtractWin32kSyscallNumberImpl: parse SSN from win32u.dll stub bytes.
 * win32u stubs are simpler: B8 [SSN 0x1000+] C2 xx xx or similar. */
static __declspec(noinline) DWORD ExtractWin32kSyscallNumberImpl(LPCSTR functionName) {
    DWORD _result = 0;
    BYTE* bytes = ResolveWin32uExportByHash(SeraphHash32(functionName));
    if (!bytes) goto _w32k_end;
    /* win32u stubs: B8 [SSN] followed by opcodes */
    for (int i = 0; i < 32; i++) {
        if (bytes[i] == 0xB8) {
            _result = _SanitiseSyscallNumW32k(*(DWORD*)(bytes + i + 1), functionName);
            if (_result) goto _w32k_end;
        }
    }
    DEBUG_SYSCALL("ExtractWin32kSyscallNumber: pattern not found for %s", functionName);
_w32k_end:
    return _result;
}

/* Thin Themida-mutation wrapper around ntoskrnl extractor. */
#pragma optimize("", off)
static __declspec(noinline) DWORD ExtractSyscallNumber(LPCSTR functionName) {
    MUTATE_START
    DWORD r = ExtractSyscallNumberImpl(functionName);
    MUTATE_END
    return r;
}
#pragma optimize("", on)

static __declspec(noinline) DWORD ExtractWin32kSyscallNumber(LPCSTR functionName) {
    return ExtractWin32kSyscallNumberImpl(functionName);
}

/* InitSyscallNumbersImpl: extract ALL syscall numbers at startup. */
#pragma optimize("", off)
static __declspec(noinline) BOOL InitSyscallNumbersImpl(void) {
    static BOOL initialized = FALSE;
    if (initialized) return TRUE;
    initialized = TRUE;
    BOOL ok = FALSE;
    DEBUG_SYSCALL("ENTER InitSyscallNumbers");


    /* P5.1: locate `syscall; ret` gadget in ntdll */
    g_SyscallGadgetVA = FindSyscallGadgetVA();
    DEBUG_SYSCALL("g_SyscallGadgetVA = 0x%llX", g_SyscallGadgetVA);

    /* ── Existing ntoskrnl syscalls ───────────────────────────────────────── */
    g_NtLoadDriverSyscall              = ExtractSyscallNumber("NtLoadDriver");
    g_NtUnloadDriverSyscall            = ExtractSyscallNumber("NtUnloadDriver");
    g_NtQuerySystemInformationSyscall  = ExtractSyscallNumber("NtQuerySystemInformation");
    g_NtOpenProcessSyscall             = ExtractSyscallNumber("NtOpenProcess");
    g_NtQueryInformationProcessSyscall = ExtractSyscallNumber("NtQueryInformationProcess");
    g_SysNtOpenFileSyscall             = ExtractSyscallNumber("NtOpenFile");
    g_SysNtDeviceIoControlFileSyscall  = ExtractSyscallNumber("NtDeviceIoControlFile");
    g_SysNtCloseSyscall                = ExtractSyscallNumber("NtClose");
    g_SysNtMapViewOfSectionSyscall     = ExtractSyscallNumber("NtMapViewOfSection");
    g_SysNtUnmapViewOfSectionSyscall   = ExtractSyscallNumber("NtUnmapViewOfSection");
    g_SysNtDuplicateObjectSyscall      = ExtractSyscallNumber("NtDuplicateObject");
    g_SysNtGetContextThreadSyscall     = ExtractSyscallNumber("NtGetContextThread");

    /* ── New ntoskrnl syscalls (Phase 1) ──────────────────────────────────── */
    g_SysNtCreateThreadExSyscall        = ExtractSyscallNumber("NtCreateThreadEx");
    g_SysNtAllocateVirtualMemorySyscall = ExtractSyscallNumber("NtAllocateVirtualMemory");
    g_SysNtProtectVirtualMemorySyscall  = ExtractSyscallNumber("NtProtectVirtualMemory");
    g_SysNtFreeVirtualMemorySyscall     = ExtractSyscallNumber("NtFreeVirtualMemory");
    g_SysNtDelayExecutionSyscall        = ExtractSyscallNumber("NtDelayExecution");
    g_SysNtTerminateProcessSyscall      = ExtractSyscallNumber("NtTerminateProcess");
    g_SysNtOpenProcessTokenSyscall      = ExtractSyscallNumber("NtOpenProcessToken");
    g_SysNtAdjustPrivilegesTokenSyscall = ExtractSyscallNumber("NtAdjustPrivilegesToken");


    /* ── Pre-resolve RtlAllocateHeap / RtlFreeHeap here ─────────────────────
     * Eliminates lazy-init race in SeraphHeapAlloc/Free on first call.
     * Both functions check s_pfnRtl* == NULL on every call — resolving them
     * here at startup means the first malloc-equivalent is already fast. */
    if (!s_pfnRtlAllocateHeap)
        s_pfnRtlAllocateHeap = (_tRtlAllocateHeap)ResolveNtdllExportByHash(
            SeraphHash32("RtlAllocateHeap"));
    if (!s_pfnRtlFreeHeap)
        s_pfnRtlFreeHeap = (_tRtlFreeHeap)ResolveNtdllExportByHash(
            SeraphHash32("RtlFreeHeap"));
    /* Pre-resolve RtlCreateUserThread — used by SeraphCreateThread.
     * More robust than NtCreateThreadEx: no SSN extraction required.
     * ntdll export — zero kernel32 involvement, works on all Win10/11 builds. */
    if (!s_pfnRtlCreateUserThread)
        s_pfnRtlCreateUserThread = (_tRtlCreateUserThread)ResolveNtdllExportByHash(
            SeraphHash32("RtlCreateUserThread"));
    DEBUG_SYSCALL("RtlCreateUserThread pfn = %p", (void*)s_pfnRtlCreateUserThread);

    /* ── win32k syscalls from win32u.dll (Phase 1) ────────────────────────── */
    g_SysNtUserSendInputSyscall        = ExtractWin32kSyscallNumber("NtUserSendInput");
    g_SysNtUserGetAsyncKeyStateSyscall = ExtractWin32kSyscallNumber("NtUserGetAsyncKeyState");

    DEBUG_SYSCALL("SSNs: NtLoadDriver=0x%X NtDeviceIoCtrl=0x%X NtClose=0x%X "
                  "NtCreateThreadEx=0x%X NtAllocVMem=0x%X NtProtVMem=0x%X "
                  "NtFreeVMem=0x%X NtDelayExec=0x%X NtTermProc=0x%X "
                  "NtUserSendInput=0x%X NtUserGAKS=0x%X",
                  g_NtLoadDriverSyscall, g_SysNtDeviceIoControlFileSyscall,
                  g_SysNtCloseSyscall,
                  g_SysNtCreateThreadExSyscall, g_SysNtAllocateVirtualMemorySyscall,
                  g_SysNtProtectVirtualMemorySyscall, g_SysNtFreeVirtualMemorySyscall,
                  g_SysNtDelayExecutionSyscall, g_SysNtTerminateProcessSyscall,
                  g_SysNtUserSendInputSyscall, g_SysNtUserGetAsyncKeyStateSyscall);

    ok = (g_NtLoadDriverSyscall != 0) &&
         (g_SysNtDeviceIoControlFileSyscall != 0) &&
         (g_SysNtCloseSyscall != 0) &&
         (g_SysNtCreateThreadExSyscall != 0) &&
         (g_SysNtDelayExecutionSyscall != 0);
    DEBUG_SYSCALL("InitSyscallNumbers: %s (win32k: SendInput=0x%X GAKS=0x%X)",
                  ok ? "OK" : "PARTIAL FAILURE",
                  g_SysNtUserSendInputSyscall, g_SysNtUserGetAsyncKeyStateSyscall);
    return ok;
}
#pragma optimize("", on)

/* Thin VM-protected wrapper. Single call between VM_START and VM_END. */
#pragma optimize("", off)
__declspec(noinline) BOOL InitSyscallNumbers(void) {
    VM_START
    BOOL ok = InitSyscallNumbersImpl();
    VM_END
    return ok;
}
#pragma optimize("", on)

/* ==========================================================================
 * SeraphHeapAlloc / SeraphHeapFree / SeraphHeapAllocZero
 * Replaces HeapAlloc/HeapFree(GetProcessHeap(), ...) with ntdll-direct path.
 *   - RtlAllocateHeap / RtlFreeHeap resolved in InitSyscallNumbers (no lazy race)
 *   - ProcessHeap from PEB+0x30 via __readgsqword(0x60) (no GetProcessHeap)
 *   - Zero kernel32 involvement, zero new VAD entry (uses existing heap)
 * NOTE: s_pfnRtlAllocateHeap / s_pfnRtlFreeHeap / typedefs declared above
 *       InitSyscallNumbersImpl to allow pre-resolution at startup.
 * ========================================================================== */
static FORCEINLINE PVOID _GetProcessHeapPEB(void) {
    /* PEB->ProcessHeap at PEB+0x30 on x64 — no GetProcessHeap() call */
    return *(PVOID*)(__readgsqword(0x60) + 0x30);
}

PVOID SeraphHeapAlloc(SIZE_T size) {
    if (!s_pfnRtlAllocateHeap) {
        s_pfnRtlAllocateHeap = (_tRtlAllocateHeap)ResolveNtdllExportByHash(
            SeraphHash32("RtlAllocateHeap"));
        if (!s_pfnRtlAllocateHeap) return NULL;
    }
    return s_pfnRtlAllocateHeap(_GetProcessHeapPEB(), 0, size);
}

PVOID SeraphHeapAllocZero(SIZE_T size) {
    if (!s_pfnRtlAllocateHeap) {
        s_pfnRtlAllocateHeap = (_tRtlAllocateHeap)ResolveNtdllExportByHash(
            SeraphHash32("RtlAllocateHeap"));
        if (!s_pfnRtlAllocateHeap) return NULL;
    }
    return s_pfnRtlAllocateHeap(_GetProcessHeapPEB(), 0x00000008 /*HEAP_ZERO_MEMORY*/, size);
}

BOOL SeraphHeapFree(PVOID p) {
    if (!p) return TRUE;
    if (!s_pfnRtlFreeHeap) {
        s_pfnRtlFreeHeap = (_tRtlFreeHeap)ResolveNtdllExportByHash(
            SeraphHash32("RtlFreeHeap"));
        if (!s_pfnRtlFreeHeap) return FALSE;
    }
    return s_pfnRtlFreeHeap(_GetProcessHeapPEB(), 0, p);
}

/* ==========================================================================
 * SeraphCreateThread — replaces CreateThread / NtCreateThreadEx.
 * Uses ntdll!RtlCreateUserThread resolved via EAT hash walk:
 *   - No SSN extraction required (NtCreateThreadEx SSN can fail on some builds)
 *   - No kernel32 involvement — ntdll only
 *   - RtlCreateUserThread wraps the proc in RtlUserThreadStart exactly as
 *     CreateThread does, so the thread proc can safely return or call ExitThread.
 * ========================================================================== */
/* ResolveKernel32ExportByHash: EAT walk on kernel32.dll for internal thread fallback.
 * "kernel32.dll" XOR-encoded with key 0x5A — no literal in .rdata. */
static BYTE* ResolveKernel32ExportByHash(DWORD nameHash) {
    static const unsigned char _e[] = {0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x00};
    WCHAR _w[13];
    for (int _i = 0; _i < 12; _i++) _w[_i] = (WCHAR)(((unsigned char)_e[_i]) ^ 0x5A);
    _w[12] = 0;
    BYTE* base = _FindModuleBase(_w);
    return _WalkEAT(base, nameHash);
}

typedef HANDLE (WINAPI* _tCreateThread_fn)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static _tCreateThread_fn s_pfnCreateThread = NULL;

HANDLE SeraphCreateThread(PVOID startRoutine, PVOID arg) {
    if (!s_pfnRtlCreateUserThread) {
        s_pfnRtlCreateUserThread = (_tRtlCreateUserThread)ResolveNtdllExportByHash(
            SeraphHash32("RtlCreateUserThread"));
    }
    HANDLE hThread = NULL;
    if (s_pfnRtlCreateUserThread) {
        NTSTATUS st = s_pfnRtlCreateUserThread(
            SERAPH_CURRENT_PROCESS,
            NULL,         /* SecurityDescriptor */
            FALSE,        /* CreateSuspended = FALSE → runs immediately */
            0,            /* StackZeroBits */
            NULL,         /* StackReserve  (use process default) */
            NULL,         /* StackCommit   (use process default) */
            startRoutine,
            arg,
            &hThread,
            NULL          /* ClientId output — not needed */
        );
        if (NT_SUCCESS(st) && hThread) {
            return hThread;
        }
        DEBUG_SYSCALL("SeraphCreateThread: RtlCreateUserThread st=0x%08X, fallback dynamic CreateThread", (ULONG)st);
    }
    if (!s_pfnCreateThread) {
        s_pfnCreateThread = (_tCreateThread_fn)(UINT_PTR)ResolveKernel32ExportByHash(
            SeraphHash32("CreateThread"));
    }
    if (s_pfnCreateThread) {
        return s_pfnCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startRoutine, arg, 0, NULL);
    }
    return NULL;
}



/* ==========================================================================
 * SeraphLoadDll / SeraphFreeDll — replace LoadLibraryW / FreeLibrary
 * Uses LdrLoadDll / LdrUnloadDll resolved from ntdll via EAT hash walk.
 * ========================================================================== */

typedef NTSTATUS (NTAPI* _tLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS (NTAPI* _tLdrUnloadDll)(PVOID);

static _tLdrLoadDll   s_pfnLdrLoadDll   = NULL;
static _tLdrUnloadDll s_pfnLdrUnloadDll = NULL;

/* _SeraphGetSystem32Path: extracts the System32 path directly from the FullDllName
 * of ntdll.dll in the PEB module list (e.g., "C:\Windows\System32\ntdll.dll" -> "C:\Windows\System32").
 * This is 100% reliable, works across all Windows builds, and is immune to missing environment blocks. */
static BOOL _SeraphGetSystem32Path(WCHAR* out, int maxChars) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb) return FALSE;
    BYTE* ldr = *(BYTE**)((BYTE*)peb + 0x18); /* PEB->Ldr at PEB+0x18 */
    if (!ldr) return FALSE;
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10); /* Ldr->InLoadOrderModuleList at +0x10 */
    LIST_ENTRY* curr = head->Flink;
    
    DWORD targetHash = SeraphHash32W(L"ntdll.dll");
    
    while (curr && curr != head) {
        USHORT nameLen = *(USHORT*)((BYTE*)curr + 0x58);  /* BaseDllName.Length */
        PWCHAR nameBuf = *(PWCHAR*) ((BYTE*)curr + 0x60); /* BaseDllName.Buffer */
        if (nameBuf && nameLen > 0) {
            DWORD h = 0xA3C59F17u;
            for (USHORT i = 0; i < nameLen / 2; i++) {
                WCHAR c = nameBuf[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                h ^= (BYTE)(c & 0xFF);
                h = (h << 5) | (h >> 27);
                h *= 0x27D4EB2Fu;
            }
            if (h == targetHash) {
                /* Found ntdll.dll. Access FullDllName at offset +0x48 */
                USHORT fullLen = *(USHORT*)((BYTE*)curr + 0x48);  /* FullDllName.Length */
                PWCHAR fullBuf = *(PWCHAR*) ((BYTE*)curr + 0x50); /* FullDllName.Buffer */
                if (fullBuf && fullLen > 0) {
                    int wLen = fullLen / 2;
                    int copyLen = wLen;
                    /* Truncate "\ntdll.dll" (9 characters) from the end */
                    if (copyLen > 9) {
                        copyLen -= 9;
                    }
                    if (copyLen >= maxChars) copyLen = maxChars - 1;
                    for (int i = 0; i < copyLen; i++) {
                        out[i] = fullBuf[i];
                    }
                    out[copyLen] = L'\0';
                    return TRUE;
                }
            }
        }
        curr = curr->Flink;
    }
    return FALSE;
}

#include "debug.h"


PVOID SeraphLoadDll(const WCHAR* dllName, PHANDLE phMod) {
    if (!s_pfnLdrLoadDll) {
        s_pfnLdrLoadDll = (_tLdrLoadDll)ResolveNtdllExportByHash(
            SeraphHash32("LdrLoadDll"));
        if (!s_pfnLdrLoadDll) {
            WLF("SeraphLoadDll: failed to resolve LdrLoadDll from ntdll export table!");
            return NULL;
        }
    }

    if (phMod) *phMod = NULL;

    /* Build System32 search path via PEB environment — prevents DLL hijacking
     * by game-local copies (Marathon ships its own winhttp.dll in its dir).
     * LdrLoadDll(NULL,...) would load the game copy; passing System32 explicitly
     * forces the correct system DLL. Falls back to NULL (default order) on failure. */
    WCHAR sys32Path[MAX_PATH];
    PWSTR searchPath = NULL;
    if (_SeraphGetSystem32Path(sys32Path, MAX_PATH)) {
        searchPath = sys32Path;
        
        char pathLog[MAX_PATH + 32];
        /* Converte WCHAR para char para escrever no log */
        int i = 0;
        while (sys32Path[i] && i < MAX_PATH - 1) { pathLog[i] = (char)sys32Path[i]; i++; }
        pathLog[i] = 0;
        
        char buf[MAX_PATH + 64];
        wsprintfA(buf, "SeraphLoadDll: searchPath resolved to '%s'", pathLog);
        WLF(buf);
    } else {
        WLF("SeraphLoadDll: _SeraphGetSystem32Path failed to resolve System32 path!");
    }


    /* Construct UNICODE_STRING inline — avoids RtlInitUnicodeString import.
     * Binary layout on x64: Length(2) MaxLength(2) [pad4] Buffer(8) = 16 bytes.
     * Matches compiler-generated layout of UNICODE_STRING from winternl.h. */
    UNICODE_STRING us;
    USHORT len = 0;
    const WCHAR* p = dllName;
    while (*p++) len++;
    us.Length        = (USHORT)(len * 2);
    us.MaximumLength = us.Length + 2;
    us.Buffer        = (PWSTR)dllName;

    /* Converte nome do DLL para ASCII para o log */
    char dllNameAscii[64];
    int di = 0;
    while (dllName[di] && di < 63) { dllNameAscii[di] = (char)dllName[di]; di++; }
    dllNameAscii[di] = 0;

    HANDLE hMod = NULL;
    NTSTATUS st = s_pfnLdrLoadDll(searchPath, NULL, &us, &hMod);
    if (!NT_SUCCESS(st)) {
        char errBuf[128];
        wsprintfA(errBuf, "SeraphLoadDll: LdrLoadDll FAILED with NTSTATUS=0x%08X for '%s'", (ULONG)st, dllNameAscii);
        WLF(errBuf);
        return NULL;
    }
    
    char okBuf[128];
    wsprintfA(okBuf, "SeraphLoadDll: LdrLoadDll successfully loaded '%s' (base=%p)", dllNameAscii, hMod);
    WLF(okBuf);


    if (phMod) *phMod = hMod;
    return hMod; /* On Windows, HMODULE == DllBase */
}

BOOL SeraphFreeDll(HANDLE hMod) {
    if (!s_pfnLdrUnloadDll) {
        s_pfnLdrUnloadDll = (_tLdrUnloadDll)ResolveNtdllExportByHash(
            SeraphHash32("LdrUnloadDll"));
        if (!s_pfnLdrUnloadDll) return FALSE;
    }
    return NT_SUCCESS(s_pfnLdrUnloadDll(hMod));
}

PVOID SeraphGetProcAddress(HANDLE hModule, const char* name) {
    if (!hModule || !name) return NULL;
    DWORD hash = SeraphHash32(name);
    return (PVOID)_WalkEAT((BYTE*)hModule, hash);
}

/* ==========================================================================
 * SysNtUserGetAsyncKeyState / SysNtUserSendInput — Direct User32 Wrappers
 *
 * Windows 11 (22H2/23H2/24H2) blocks Win32k system calls invoked via ntdll
 * indirect gadgets with STATUS_INVALID_SYSTEM_SERVICE.
 * Resolving user32!GetAsyncKeyState and user32!SendInput directly via PEB/EAT
 * hash walking ensures 100% reliable key detection and mouse injection across
 * all Windows 10 and Windows 11 builds.
 * ========================================================================== */
SHORT SysNtUserGetAsyncKeyState(int vKey) {
    if (!s_pfnGetAsyncKeyState_fb) {
        s_pfnGetAsyncKeyState_fb = (_tGetAsyncKeyState_fb)(UINT_PTR)ResolveUser32ExportByHash(
            SeraphHash32("GetAsyncKeyState"));
    }
    if (s_pfnGetAsyncKeyState_fb)
        return s_pfnGetAsyncKeyState_fb(vKey);
    return GetAsyncKeyState(vKey);
}

UINT SysNtUserSendInput(UINT cInputs, LPINPUT pInputs, int cbSize) {
    if (!s_pfnSendInput_fb) {
        s_pfnSendInput_fb = (_tSendInput_fb)(UINT_PTR)ResolveUser32ExportByHash(
            SeraphHash32("SendInput"));
    }
    if (s_pfnSendInput_fb)
        return s_pfnSendInput_fb(cInputs, pInputs, cbSize);
    return SendInput(cInputs, pInputs, cbSize);
}


