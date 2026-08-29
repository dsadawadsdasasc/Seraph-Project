
#include "ThemidaSDK.h"
#include "evasion_user.h"
#ifndef SERAPH_BUILD_STUB
#include "byovd.h"      /* BYOVD_FindProcessInfo, BYOVD_ReadVA — payload only */
#endif
#include "syscalls.h"   /* SysNtQueryInformationProcess — direct syscall, not hookable */
#include "XorStr.h"
#include "xor_strings.h"
#include "debug.h"
#include <intrin.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef SERAPH_DMA_BUILD
/* DMA build requires no local evasion logic */
VOID UeInitializeEvasion(PEVASION_CONTEXT c) {
    if(c){
        c->delay_ms=0; c->is_vm=FALSE; c->is_sandbox=FALSE; c->is_debugged=FALSE;
    }
}
BOOLEAN CheckSandbox() { return FALSE; }
PVOID UeAllocateStealthMemory(SIZE_T s){return SeraphVAlloc(s,PAGE_READWRITE);}
VOID UeProtectMemory(PVOID a,SIZE_T s,DWORD p){SeraphVProtect(a,s,p,NULL);}
VOID UeFreeStealthMemory(PVOID a){SeraphVFree(a);}
VOID UeDelayExecution(PEVASION_CONTEXT c){ (void)c; }
BOOLEAN CheckDebugger() { return FALSE; }
BOOLEAN CheckHardwareBreakpoints() { return FALSE; }
BOOLEAN CheckNtGlobalFlag() { return FALSE; }
DWORD GetProcessIdByName(const WCHAR* processName) { return 0; }
PVOID GetProcessBaseAddress(DWORD pid) { return NULL; }
PVOID GetDestiny2BaseAddress(void) { return NULL; }
#else


/* Use SDK's PEB definition; we only need NtGlobalFlag offset */
VOID UeInitializeEvasion(PEVASION_CONTEXT c){
    DEBUG_EVASION("ENTER UeInitializeEvasion");
    if(!c){
        DEBUG_EVASION("Context is NULL, returning");
        return;
    }
    c->delay_ms=500+(GetTickCount()%1500);
    DEBUG_EVASION("Delay set to %lu ms", c->delay_ms);
    
    BOOLEAN sandbox = CheckSandbox();
    c->is_vm = sandbox;
    c->is_sandbox = sandbox;
    DEBUG_EVASION("Sandbox check: %d, is_vm: %d, is_sandbox: %d",
                  sandbox, c->is_vm, c->is_sandbox);
    
    BOOLEAN debugger = CheckDebugger();
    BOOLEAN hwbp = CheckHardwareBreakpoints();
    BOOLEAN ntGlobal = CheckNtGlobalFlag();
    c->is_debugged = debugger || hwbp || ntGlobal;
    DEBUG_EVASION("Debug checks: debugger=%d, hwbp=%d, ntGlobal=%d, is_debugged=%d",
                  debugger, hwbp, ntGlobal, c->is_debugged);
    
    DEBUG_EVASION("EXIT UeInitializeEvasion");
}

#pragma optimize("", off)
__declspec(noinline) BOOLEAN CheckSandbox(){
    MUTATE_START
    BOOLEAN _r = FALSE;
    DEBUG_EVASION("ENTER CheckSandbox");
    HKEY h;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,DXOR_A(ENC_sandbox_key),0,KEY_READ,&h)==0){
        DEBUG_EVASION("Sandboxie registry key found - sandbox detected");
        RegCloseKey(h);
        _r = TRUE; goto _cs_end;
    }
    DEBUG_EVASION("No sandbox detected");
_cs_end:
    MUTATE_END
    return _r;
}
#pragma optimize("", on)
PVOID UeAllocateStealthMemory(SIZE_T s){return SeraphVAlloc(s,PAGE_NOACCESS);}
VOID UeProtectMemory(PVOID a,SIZE_T s,DWORD p){SeraphVProtect(a,s,p,NULL);}
VOID UeFreeStealthMemory(PVOID a){SeraphVFree(a);}
VOID UeDelayExecution(PEVASION_CONTEXT c){
    if(!c)return;
    /* P14 → Phase1: SysNtDelayExecution syscall direto — zero GetProcAddress,
       zero GetModuleHandleW, RIP aparece em ntdll via gadget indireto. */
    LARGE_INTEGER d; d.QuadPart=-((LONGLONG)c->delay_ms*10000LL);
    SysNtDelayExecution(FALSE,&d);
}

/* Anti-debug techniques */
#pragma optimize("", off)
__declspec(noinline) BOOLEAN CheckDebugger() {
    MUTATE_START
    BOOLEAN _r = FALSE;
    DEBUG_EVASION("ENTER CheckDebugger");
    /* Read PEB.BeingDebugged directly — avoids IsDebuggerPresent IAT entry
     * which anti-cheats scan for. PEB at GS:[0x60], BeingDebugged at +0x02. */
    {
        PPEB _peb = (PPEB)__readgsqword(0x60);
        if (_peb && *(BYTE*)((BYTE*)_peb + 0x02)) {
            DEBUG_EVASION("PEB.BeingDebugged is set");
            _r = TRUE; goto _cd_end;
        }
    }
    DEBUG_EVASION("PEB.BeingDebugged check passed");
    /* P15: delays aleatórios entre as 3 chamadas de anti-debug
     * para quebrar o fingerprint de triplet QSIP rápido */
    ULONG_PTR debugPort = 0;
    /* Decoy: leitura inócua de PEB.OSVersion para misturar o padrão */
    { PPEB p = (PPEB)__readgsqword(0x60);
      if (p) { volatile DWORD _dummy = *(DWORD*)((BYTE*)p + 0x118); (void)_dummy; } }
    if (NT_SUCCESS(SysNtQueryInformationProcess(SERAPH_CURRENT_PROCESS, 7, &debugPort, sizeof(debugPort), NULL)) && debugPort) {
        DEBUG_EVASION("ProcessDebugPort detected: 0x%p", debugPort);
        _r = TRUE; goto _cd_end;
    }
    DEBUG_EVASION("ProcessDebugPort check passed (no debug port)");
    /* P15: mini delay aleatório 1-4ms entre chamadas — ponteiro cacheado */
    { LARGE_INTEGER _w; _w.QuadPart=-((LONGLONG)(1000+(GetTickCount()&0x3)*1000)*10); SysNtDelayExecution(FALSE,&_w); }
    HANDLE debugObject = NULL;
    if (NT_SUCCESS(SysNtQueryInformationProcess(SERAPH_CURRENT_PROCESS, 30, &debugObject, sizeof(debugObject), NULL)) && debugObject) {
        DEBUG_EVASION("ProcessDebugObjectHandle detected: 0x%p", debugObject);
        SysNtClose(debugObject);
        _r = TRUE; goto _cd_end;
    }
    DEBUG_EVASION("ProcessDebugObjectHandle check passed (no debug object)");
    { LARGE_INTEGER _w; _w.QuadPart=-((LONGLONG)(2000+(GetTickCount()&0x1)*2000)*10); SysNtDelayExecution(FALSE,&_w); }
    ULONG debugFlags = 0;
    if (NT_SUCCESS(SysNtQueryInformationProcess(SERAPH_CURRENT_PROCESS, 31, &debugFlags, sizeof(debugFlags), NULL)) && debugFlags == 0) {
        DEBUG_EVASION("ProcessDebugFlags indicates debugging (flags=0)");
        _r = TRUE; goto _cd_end;
    }
    DEBUG_EVASION("ProcessDebugFlags check passed (flags=0x%X)", debugFlags);
    DEBUG_EVASION("EXIT CheckDebugger - no debugger detected");
_cd_end:
    MUTATE_END
    return _r;
}
#pragma optimize("", on)

#pragma optimize("", off)
__declspec(noinline) BOOLEAN CheckHardwareBreakpoints() {
    MUTATE_START
    BOOLEAN _r = FALSE;
    DEBUG_EVASION("ENTER CheckHardwareBreakpoints");
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    /* Use direct syscall (NtGetContextThread) instead of GetThreadContext.
     * GetThreadContext is hooked by BattlEye; the NT syscall bypasses the hook. */
    NTSTATUS ctxStatus = SysNtGetContextThread(GetCurrentThread(), &ctx);
    if (NT_SUCCESS(ctxStatus)) {
        DEBUG_EVASION("Debug registers: Dr0=0x%p, Dr1=0x%p, Dr2=0x%p, Dr3=0x%p",
                      ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3);
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            DEBUG_EVASION("Hardware breakpoints detected");
            _r = TRUE; goto _chbp_end;
        }
        DEBUG_EVASION("No hardware breakpoints detected");
    } else {
        DEBUG_EVASION("NtGetContextThread failed (0x%08X)", ctxStatus);
    }
    DEBUG_EVASION("EXIT CheckHardwareBreakpoints - no hardware breakpoints");
_chbp_end:
    MUTATE_END
    return _r;
}
#pragma optimize("", on)

#pragma optimize("", off)
__declspec(noinline) BOOLEAN CheckNtGlobalFlag() {
    MUTATE_START
    BOOLEAN _r = FALSE;
    DEBUG_EVASION("ENTER CheckNtGlobalFlag");
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb) {
        ULONG ntGlobalFlag = *(ULONG*)((BYTE*)peb + 0xBC);
        DEBUG_EVASION("PEB NtGlobalFlag = 0x%X", ntGlobalFlag);
        if (ntGlobalFlag & 0x70) {
            DEBUG_EVASION("NtGlobalFlag indicates debugging (flags 0x%X)", ntGlobalFlag);
            _r = TRUE; goto _cngf_end;
        }
        DEBUG_EVASION("NtGlobalFlag check passed (no debug flags)");
    } else {
        DEBUG_EVASION("Failed to read PEB");
    }
    DEBUG_EVASION("EXIT CheckNtGlobalFlag - no debug flags");
_cngf_end:
    MUTATE_END
    return _r;
}
#pragma optimize("", on)

/* ============================================================================
 * Process utilities using direct syscalls for stealth
 * ============================================================================ */

#include "syscalls.h"

// Get process ID by name using NtQuerySystemInformation (SystemProcessInformation)
DWORD GetProcessIdByName(const WCHAR* processName) {
    DEBUG_EVASION("ENTER GetProcessIdByName: %ls", processName);
    NTSTATUS status = 0;
    ULONG bufferSize = 0x10000; // Start with 64KB
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    PVOID buffer = NULL;
    DWORD pid = 0;

    /* P3: Query real size of SystemProcessInformation via NtQuerySystemInformation
     * rather than guessing/multiplying by 2. This is robust and prevents virtual memory bloat. */
    for (int attempts = 0; attempts < 6; attempts++) {
        buffer = SeraphHeapAlloc(bufferSize);
        if (!buffer) {
            DEBUG_EVASION("SeraphHeapAlloc failed (size=%lu)", bufferSize);
            return 0;
        }
        ULONG needed = 0;
        status = SysNtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &needed);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            SeraphHeapFree(buffer);
            buffer = NULL;
            bufferSize = needed + 0x2000; /* Add safety pad */
            if (bufferSize > 0x4000000) { /* 64MB cap */
                DEBUG_EVASION("GetProcessIdByName: needed size exceeds 64MB");
                return 0;
            }
            continue;
        }
        break;
    }

    if (!buffer) return 0;

    if (!NT_SUCCESS(status)) {
        DEBUG_EVASION("SysNtQuerySystemInformation failed: 0x%X", status);
        SeraphHeapFree(buffer);
        return 0;
    }

    // Iterate through process list
    spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (spi) {
        if (spi->ImageName.Buffer) {
            // Compare case-insensitive
            if (_wcsicmp(spi->ImageName.Buffer, processName) == 0) {
                pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
                DEBUG_EVASION("Found process %ls with PID %lu", processName, pid);
                break;
            }
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
    }

    SeraphHeapFree(buffer);
    DEBUG_EVASION("EXIT GetProcessIdByName: returning PID %lu", pid);
    return pid;
}

// Get process base address using NtQueryInformationProcess (ProcessBasicInformation -> PEB)
/* GetProcessBaseAddress: legacy function kept for API compatibility.
 * SAFE: reads PEB.ImageBaseAddress via physical memory engine (BYOVD_ReadVA).
 * Zero syscalls on target process -- invisible to EtwTi and ObCallbacks.
 * Requires BYOVD_Init() to have been called first. */
PVOID GetProcessBaseAddress(DWORD pid) {
#ifdef SERAPH_BUILD_STUB
    /* Stub não tem BYOVD ainda; retorna NULL. Stub não precisa ler PEB de outros processos. */
    (void)pid; return NULL;
#else
    DEBUG_EVASION("ENTER GetProcessBaseAddress (physical path) PID=%lu", pid);

    /* We need the process name to use BYOVD_FindProcessInfo.
     * Query it via NtQuerySystemInformation (already a direct syscall). */
    ULONG szNeeded = 0;
    SysNtQuerySystemInformation(5 /*SystemProcessInformation*/, NULL, 0, &szNeeded);
    if (!szNeeded) return NULL;
    szNeeded += 0x4000;
    BYTE *buf = (BYTE*)SeraphHeapAllocZero(szNeeded);
    if (!buf) return NULL;
    NTSTATUS ns = SysNtQuerySystemInformation(5, buf, szNeeded, &szNeeded);
    char nameA[20] = {0};
    if (NT_SUCCESS(ns)) {
        /* Walk SYSTEM_PROCESS_INFORMATION list to find matching PID */
        BYTE *p = buf;
        while (1) {
            DWORD *nextOff = (DWORD*)p;
            ULONG_PTR *pidPtr = (ULONG_PTR*)(p + 0x50);
            if ((DWORD)*pidPtr == pid) {
                /* ImageName UNICODE_STRING at +0x38 (Length+2, MaxLen+2, Buffer*+8 = 0x0C on x64 = offset 0x38) */
                USHORT len  = *(USHORT*)(p + 0x38);
                PWSTR  wbuf = *(PWSTR* )(p + 0x40);
                if (wbuf && len > 0 && len <= 38) {
                    WideCharToMultiByte(CP_ACP, 0, wbuf, len/2, nameA, 19, NULL, NULL);
                }
                break;
            }
            if (!*nextOff) break;
            p += *nextOff;
        }
    }
    SeraphHeapFree(buf);
    if (!nameA[0]) { DEBUG_EVASION("GetProcessBaseAddress: name not found for PID %lu", pid); return NULL; }

    UINT64 cr3 = 0, pebVA = 0;
    if (!BYOVD_FindProcessInfo(nameA, &cr3, &pebVA) || !cr3 || !pebVA) {
        DEBUG_EVASION("GetProcessBaseAddress: BYOVD_FindProcessInfo failed for '%s'", nameA);
        return NULL;
    }
    /* PEB+0x10 = ImageBaseAddress (x64 Win10 22H2) */
    PVOID base = NULL;
    BYOVD_ReadVA(cr3, pebVA + 0x10, &base, sizeof(base));
    DEBUG_EVASION("GetProcessBaseAddress: base=0x%p (via physical)", base);
    return base;
#endif /* SERAPH_BUILD_STUB */
}

/* GetDestiny2BaseAddress: uses physical engine directly -- no handle opened,
 * no ReadProcessMemory, no NtOpenProcess. Invisible to BE kernel callbacks. */
PVOID GetDestiny2BaseAddress(void) {
#ifdef SERAPH_BUILD_STUB
    /* Stub não ataca o jogo — esse path só é chamado pelo payload. */
    return NULL;
#else
    DEBUG_EVASION("ENTER GetDestiny2BaseAddress (physical path)");
    UINT64 cr3 = 0, pebVA = 0;
    /* XOR-decoded "destiny2.exe" (key=0x4B) */
    char _d2[14];
    { static const char _e[]={0x2F,0x2E,0x38,0x3F,0x22,0x25,0x32,0x79,0x65,0x2E,0x33,0x2E,0x00};
      for(int i=0;i<12;i++) _d2[i]=_e[i]^0x4B; _d2[12]=0; }
    if (!BYOVD_FindProcessInfo(_d2, &cr3, &pebVA) || !cr3 || !pebVA) {
        DEBUG_EVASION("Destiny2 not found in EPROCESS list");
        return NULL;
    }
    PVOID base = NULL;
    BYOVD_ReadVA(cr3, pebVA + 0x10, &base, sizeof(base));
    DEBUG_EVASION("Destiny2 base=0x%p cr3=0x%llX peb=0x%llX", base, cr3, pebVA);
    return base;
#endif /* SERAPH_BUILD_STUB */
}

#endif /* SERAPH_DMA_BUILD */

VOID UeErasePEHeader(void) {
    /* Localiza a base do módulo atual diretamente via PEB->ImageBaseAddress (PEB+0x10 no x64).
     * Substitui GetModuleHandleW(NULL) — zero IAT, zero kernel32. */
    PVOID base = *(PVOID*)(__readgsqword(0x60) + 0x10);
    if (!base) return;

    /* A proteção inicial costuma ser PAGE_READONLY. Alteramos temporariamente para PAGE_READWRITE.
     * Para manter compatibilidade com a inicialização de TLS do Windows em novos threads (ex: ByovdInitThread),
     * não podemos limpar os 4096 bytes inteiros, pois isso destruiria a tabela de diretórios de dados (incluindo o TLS Directory).
     * Em vez disso, limpamos cirurgicamente apenas o cabeçalho DOS (primeiros 60 bytes), mantendo o ponteiro e_lfanew
     * (no offset 0x3C) e o cabeçalho PE completo intactos. Isso quebra ferramentas de dump (que buscam pela assinatura 'MZ')
     * mas mantém a criação de threads e TLS funcionando 100% perfeitamente. */
    ULONG oldProtect = 0;
    if (SeraphVProtect(base, 64, PAGE_READWRITE, &oldProtect)) {
        SecureZeroMemory(base, 0x3C);
        SeraphVProtect(base, 64, oldProtect, &oldProtect);
        DEBUG_EVASION("UeErasePEHeader: DOS header erased (kept e_lfanew) successfully at base %p", base);
    } else {
        DEBUG_EVASION("UeErasePEHeader: SeraphVProtect PAGE_READWRITE failed");
    }
}

