/* stub_entry.c — Entry point of Stub.exe.
 *
 * Replaces the legacy Loader/loader.c::wWinMain.  The stub's job is:
 *
 *   1. Apply process mitigation policies (DEP, ASLR, image-load, CFG).
 *   2. Single-instance mutex (UUID derived from volume serial).
 *   3. HVCI / SecureBoot gate via InitializeChecks().
 *   4. Spoof PEB image/cmdline → "RuntimeBroker.exe -Embedding".
 *   5. Stub_RunLoginPhase() — D2D login, KeyAuth, returns creds.
 *   6. Resolve the payload (svc.dll):
 *        - Phase 2 (current): LoadLibraryW on a local plaintext svc.dll
 *          sitting next to Stub.exe.  This is the C1 checkpoint.
 *        - Phase 3 (P3.x):    HTTPS download + AES-GCM decrypt → %TEMP%
 *                             then LoadLibrary, delete file.
 *        - Phase 4 (P4.x):    HTTPS download + decrypt → manual map
 *                             entirely in memory, no disk artefact.
 *   7. Build PayloadCtx and call PayloadMain via the resolved entry.
 *   8. Cleanup mutex / dbg buf / Free the loaded module / exit.
 *
 * The current implementation is the Phase 2 LoadLibrary path.  Phase 3.x
 * and Phase 4.x edit the marked block (`STUB_PAYLOAD_RESOLVE`) without
 * touching the rest of this file.
 *
 * Build flag SERAPH_BUILD_STUB:
 *   - Defined when this TU is compiled into Stub.exe.
 *   - Triggers PAYLOAD_API → __declspec(dllimport) for PayloadMain so the
 *     symbol resolves through the LoadLibrary'd module's export table.
 *   - However, since we resolve PayloadMain dynamically via
 *     GetProcAddress, the import declaration is essentially decorative.
 *     We use a function pointer typedef'd from the prototype.
 */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stub_login.h"
#include "stub_crypto.h"
#include "stub_transport.h"
#include "stub_pe_parser.h"
#include "stub_victim.h"
#include "stub_stomp.h"
#include "stub_evasion.h"   /* Fase 8: InvertedFunctionTable + PEB unlink */
#include "antire.h"
#include "antire_handles.h"
#include "gui.h"             /* DbgBuf_* */

#include "../Loader/payload_ctx.h"
#include "../Loader/payload_entry.h" // For PFN_PayloadMain typedef

HANDLE g_hCloseLoadingEvent = NULL;
HANDLE g_hLoadingDestroyedEvent = NULL;

void __cdecl Stub_CloseLoadingScreen(void) {
    if (g_hCloseLoadingEvent) {
        SetEvent(g_hCloseLoadingEvent);
        if (g_hLoadingDestroyedEvent) {
            WaitForSingleObject(g_hLoadingDestroyedEvent, INFINITE);
        }
    }
}

void __cdecl Stub_UpdateLoadingText(const wchar_t* text) {
    Stub_SetLoadingText(text);
}

#include "checks.h"        /* InitializeChecks, ShowCheckUI, g_checks */
#include "debug_buffer.h"  /* DbgBuf_Init / DbgBuf_Free */
#include "evasion_user.h"  /* CheckDebugger / CheckHardwareBreakpoints */
#include "syscalls.h"       /* InitSyscallNumbers (P5.1 gadget) */
#include "self_hash.h"      /* P6.1: self-integrity check */
#include "keyauth.h"        /* P7.2: KeyAuth_GetVarString for URL rotation */
#include "ThemidaSDK.h"
#include "payload_ctx.h"
#include "payload_entry.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef STUB_VER
#define STUB_VER 0
#endif

/* Function-pointer alias for the dynamically-resolved entry. */
typedef int (__cdecl *PFN_PayloadMain)(const PayloadCtx*);

/* DbgBuf_Init / Free — provided by debug_buffer.c, also linked into the stub. */

/* ── Process mitigation policy hardening ───────────────────────────────────
 * Applied as early as possible in wWinMain.  Each call is best-effort —
 * older Windows builds may not support every policy.  We don't gate
 * execution on success because many of these are advisory, and a couple
 * (dynamic-code prohibit) get re-applied LATER, after the manual map
 * completes, with stricter flags. */
static void Stub_ApplyMitigationPolicies(void) {
    /* DEP — non-executable data pages.  Default-on for x64 but explicit
     * here belts-and-braces. */
    {
        PROCESS_MITIGATION_DEP_POLICY p = {0};
        p.Enable = 1;
        p.Permanent = 1;
        SetProcessMitigationPolicy(ProcessDEPPolicy, &p, sizeof(p));
    }
    /* ASLR — force relocation of dynamic libraries; deny low addresses. */
    {
        PROCESS_MITIGATION_ASLR_POLICY p = {0};
        p.EnableForceRelocateImages = 1;
        p.EnableHighEntropy         = 1;
        p.DisallowStrippedImages    = 1;
        SetProcessMitigationPolicy(ProcessASLRPolicy, &p, sizeof(p));
    }
    /* Image-load restrict: forbid loading from remote shares + low-IL
     * folders.  Not as strict as System32-only (that's done at every
     * LoadLibrary call site), but a useful blanket. */
    {
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY p = {0};
        p.NoRemoteImages = 1;
        p.NoLowMandatoryLabelImages = 1;
        SetProcessMitigationPolicy(ProcessImageLoadPolicy, &p, sizeof(p));
    }
    /* Extension-point disable: blocks AppInit_DLLs / SetWindowsHookEx
     * legacy hooks → defends against injection of analysis DLLs. */
    {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY p = {0};
        p.DisableExtensionPoints = 1;
        SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &p, sizeof(p));
    }
}

/* Build a randomised mutex name from volume serial — single instance.
 * Identical algorithm to legacy loader.c (so re-launch-as-admin path,
 * which spawns a child, still detects the parent's mutex). */
static void Stub_BuildMutexName(WCHAR* out64) {
    DWORD volSerial = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    DWORD h1 = volSerial;
    DWORD h2 = (h1 * 0x9E3779B9u) ^ 0x3C4A7F12u; h2 = (h2 << 13) | (h2 >> 19);
    DWORD h3 = (h2 * 0x9E3779B9u) ^ 0xB1E2D4C8u; h3 = (h3 <<  7) | (h3 >> 25);
    DWORD h4 = (h3 * 0x9E3779B9u) ^ 0x7A4F2E9Bu; h4 = (h4 << 17) | (h4 >> 15);
    wsprintfW(out64, L"Global\\{%08X-%04X-%04X-%04X-%08X%04X}",
              h1,
              (WORD)(h2 >> 16), (WORD)(h2 & 0xFFFF),
              (WORD)(h3 >> 16),
              h4, (WORD)(h3 & 0xFFFF));
}

/* ── Resolve & call PayloadMain ────────────────────────────────────────────
 * Phase 2 implementation (current): LoadLibraryW on local svc.dll.
 * Returns the int returned by PayloadMain, or -1000 if anything in the
 * resolution path fails.
 *
 * IMPORTANT: We use LoadLibraryExW with LOAD_LIBRARY_SEARCH_APPLICATION_DIR
 * | LOAD_LIBRARY_SEARCH_SYSTEM32 to forbid any DLL hijack from the CWD or
 * %PATH%.  Only the directory containing Stub.exe and System32 are
 * searched.  This closes the side-load attack on this load. */
/* P3.4 + P4-alt — Download → HMAC verify → AES-GCM decrypt → MODULE STOMPING
 * in-memory contra DLL vítima legítima → exec PayloadMain → revert.
 *
 * Sem disk drop, sem LoadLibrary do payload, sem novas páginas executáveis.
 * Único log ETW potencial: VirtualProtect na vítima durante o memcpy
 * (in-self, BEClient não monitora processos arbitrários por esse vetor).
 *
 * Returns negative error on any step failure; PayloadMain's int rc on success.
 */
__declspec(noinline) static int Stub_DownloadDecryptAndRun(StubLoginResult* login) {
    VM_START
    int rc = -1100;
    BYTE*  blob   = NULL;  SIZE_T blobLen  = 0;
    BYTE*  plain  = NULL;  SIZE_T plainLen = 0;
    StubPE pe = {0};
    StubVictim victim = {0};
    BOOL stomped = FALSE;

    StubTransportCfg tcfg;
    tcfg.host      = L"raw.githubusercontent.com";
    tcfg.manifest  = L"/dsadawadsdasasc/svc-releases/main/manifest.json";
    tcfg.payload   = L"/dsadawadsdasasc/svc-releases/main/svc.bin";
    tcfg.timeoutMs = 15000;

    /* P7.2 — URL rotation: KeyAuth var `payload_url` no formato
     *   "host|/path/to/svc.bin"     (manifest opcional via `manifest_url`)
     * Permite trocar mirror sem rebuilds.  Caller frees com free().  */
    static WCHAR s_hostBuf[256];
    static WCHAR s_pathBuf[512];
    char* urlVar = KeyAuth_GetVarString("payload_url");
    if (urlVar) {
        char* sep = strchr(urlVar, '|');
        if (sep) {
            *sep = 0;
            int n1 = MultiByteToWideChar(CP_UTF8, 0, urlVar, -1,
                                          s_hostBuf, _countof(s_hostBuf));
            int n2 = MultiByteToWideChar(CP_UTF8, 0, sep + 1, -1,
                                          s_pathBuf, _countof(s_pathBuf));
            if (n1 > 0 && n2 > 0) {
                tcfg.host    = s_hostBuf;
                tcfg.payload = s_pathBuf;
                WriteLogFile("Stub: payload URL from KeyAuth var");
            }
        }
        SecureZeroMemory(urlVar, strlen(urlVar) + 1);
        free(urlVar);
    }

    /* 1. download blob cifrado */
    Stub_SetLoadingText(L"Loading cheat... [Downloading]");
    WriteLogFile("Stub: downloading payload");
    if (Stub_DownloadPayload(&tcfg, &blob, &blobLen) != 0) {
        WriteLogFile("Stub: payload download failed");
        rc = -1101; goto cleanup;
    }

    /* 2. HMAC verify + AES-GCM decrypt */
    Stub_SetLoadingText(L"Loading cheat... [Decrypting]");
    int dr = Stub_VerifyAndDecrypt(blob, blobLen,
                                   login->aes_key, login->hmac_key,
                                   &plain, &plainLen);
    if (dr != 0) {
        WriteLogFile("Stub: payload verify/decrypt failed");
        rc = -1102; goto cleanup;
    }

    /* 2.1 P7.1 — desempacotar header de polimorfismo SP01:
     *      [0..3] magic 'SP01' | [4..7] real_size LE | [8..] svc.dll bytes + padding
     *  Verificamos o magic, extraímos real_size e descartamos padding random. */
    if (plainLen < 8 || memcmp(plain, "SP01", 4) != 0) {
        WriteLogFile("Stub: payload poly header missing/invalid");
        rc = -1107; goto cleanup;
    }
    DWORD realSize = *(DWORD*)(plain + 4);
    if (realSize == 0 || (SIZE_T)8 + realSize > plainLen) {
        WriteLogFile("Stub: poly header real_size invalid");
        rc = -1108; goto cleanup;
    }
    BYTE*  pePtr = plain + 8;
    SIZE_T peLen = realSize;

    /* 3. parse PE */
    Stub_SetLoadingText(L"Loading cheat... [PE Parse]");
    if (StubPE_Parse(&pe, pePtr, peLen) != 0) {
        WriteLogFile("Stub: PE parse failed");
        rc = -1103; goto cleanup;
    }

    /* 4. escolha de DLL vítima */
    Stub_SetLoadingText(L"Loading cheat... [Victim Pick]");
    if (StubVictim_Pick(&victim, pe.sizeOfImage) != 0) {
        WriteLogFile("Stub: no victim DLL fits");
        rc = -1104; goto cleanup;
    }

    /* 5. stomping */
    Stub_SetLoadingText(L"Loading cheat... [Stomp]");
    PFN_PayloadMain pPayloadMain = NULL;
    int sr = StubStomp_Apply(&pe, &victim, &pPayloadMain);
    if (sr != 0 || !pPayloadMain) {
        WriteLogFile("Stub: stomp apply failed");
        rc = -1105; goto cleanup;
    }
    stomped = TRUE;

    /* Initialize C++ Runtime and call global constructors inside the payload */
    if (pe.entryRVA) {
        typedef BOOL (WINAPI* LPDLLMAIN)(HINSTANCE, DWORD, LPVOID);
        LPDLLMAIN pDllMain = (LPDLLMAIN)(victim.baseVA + pe.entryRVA);
        WriteLogFile("Stub: calling DllMain(ATTACH)");
        pDllMain((HINSTANCE)victim.baseVA, DLL_PROCESS_ATTACH, NULL);
    }

    /* 5.1 Fase 8 — Tier-S evasão: patch InvertedFunctionTable + PEB unlink.
     * Falhas aqui são não-fatais (perde só camada extra). */
    Stub_SetLoadingText(L"Loading cheat... [Evasion Patch]");
    StubEvasion_PatchInvertedTable(&pe, &victim);
    StubEvasion_UnlinkPEBEntry(&victim);
    Stub_SetLoadingText(L"Loading cheat... [Initializing]");

    /* Wipe plaintext já que a imagem foi copiada na vítima. */
    Stub_FreeBuf(plain, plainLen); plain = NULL; plainLen = 0;

    /* 6. PayloadCtx + chamada */
    PayloadCtx ctx;
    PayloadCtx_Init(&ctx);
    ctx.hStubInstance     = GetModuleHandleW(NULL);
    ctx.payloadBase       = (PVOID)victim.baseVA;
    ctx.payloadSize       = pe.sizeOfImage;
    ctx.stub_pid          = GetCurrentProcessId();
    ctx.LogFn             = WriteLogFile;
    ctx.SetHotRevertFn    = AntiRE_Handles_SetHotRevert;
    ctx.SetD2PidFn        = AntiRE_Handles_SetD2Pid;
    ctx.CloseLoadingScreenFn = Stub_CloseLoadingScreen;
    ctx.SetLoadingTextFn  = Stub_UpdateLoadingText;
    ctx.stub_build_ver    = STUB_VER;
    ctx.payload_build_ver = login->payload_version;
    {
        size_t i;
        for (i = 0; i < (PAYLOAD_CTX_USERNAME_CCH - 1) && login->username[i]; i++)
            ctx.username[i] = login->username[i];
        ctx.username[i] = 0;
    }
    strncpy_s(ctx.session_id, sizeof(ctx.session_id), login->session_id, _TRUNCATE);
    strncpy_s(ctx.hwid,       sizeof(ctx.hwid),       login->hwid,       _TRUNCATE);

    { char _b[128]; wsprintfA(_b, "Stub: ctx cbSize=%lu magic=0x%08X abi=%lu sizeof=%lu",
        ctx.cbSize, ctx.magic, ctx.abi_version, (ULONG)sizeof(PayloadCtx)); WriteLogFile(_b); }
    WriteLogFile("Stub: calling PayloadMain (stomp path)");
    rc = pPayloadMain(&ctx);
    { char _b[64]; wsprintfA(_b, "Stub: PayloadMain returned %d", rc); WriteLogFile(_b); }
    SecureZeroMemory(&ctx, sizeof(ctx));

cleanup:
    if (stomped) {
        if (pe.entryRVA) {
            typedef BOOL (WINAPI* LPDLLMAIN)(HINSTANCE, DWORD, LPVOID);
            LPDLLMAIN pDllMain = (LPDLLMAIN)(victim.baseVA + pe.entryRVA);
            WriteLogFile("Stub: calling DllMain(DETACH)");
            pDllMain((HINSTANCE)victim.baseVA, DLL_PROCESS_DETACH, NULL);
        }
        StubEvasion_RelinkPEBEntry();
        StubEvasion_RestoreInvertedTable();
        StubStomp_Revert(&victim);
    }
    StubVictim_FreeSnapshot(&victim);
    if (victim.hMod) FreeLibrary(victim.hMod);
    if (plain) Stub_FreeBuf(plain, plainLen);
    if (blob)  Stub_FreeBuf(blob,  blobLen);
    VM_END
    return rc;
}

__declspec(noinline) static int Stub_LoadAndRunPayload(StubLoginResult* login) {
    MUTATE_START
    int rc = -1000;
    /* Router: if KeyAuth handed us non-zero AES + HMAC, use the Phase 3
     * download+decrypt path.  Otherwise fall back to Phase 2 LoadLibrary
     * on a local svc.dll (developer / offline build). */
    BYTE zero[32] = {0};
    BOOL hasKeys = (memcmp(login->aes_key,  zero, 32) != 0) &&
                   (memcmp(login->hmac_key, zero, 32) != 0);
    if (hasKeys) {
        WriteLogFile("Stub: using Phase 3 download+decrypt path");
        rc = Stub_DownloadDecryptAndRun(login);
        goto done;
    }

    WriteLogFile("Stub: using Phase 2 local svc.dll path");
    Stub_SetLoadingText(L"Loading cheat... [Local svc.dll]");
    HMODULE hPayload = NULL;

    hPayload = LoadLibraryExW(L"svc.dll", NULL,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hPayload) {
        WriteLogFile("Stub: LoadLibraryExW(svc.dll) failed");
        rc = -1001;
        goto done;
    }
    PFN_PayloadMain pPayloadMain =
        (PFN_PayloadMain)GetProcAddress(hPayload, "PayloadMain");
    if (!pPayloadMain) {
        WriteLogFile("Stub: GetProcAddress(PayloadMain) failed");
        FreeLibrary(hPayload);
        rc = -1002;
        goto done;
    }

    /* Build PayloadCtx with what Phase 2 has available.  Phase 3 fills
     * session_id / hwid / winhttp handles after KeyAuth_GetPayloadKeys. */
    PayloadCtx ctx;
    PayloadCtx_Init(&ctx);
    ctx.hStubInstance     = GetModuleHandleW(NULL);
    ctx.payloadBase       = (PVOID)hPayload;
    ctx.payloadSize       = 0;  /* unknown via LoadLibrary; mapper fills in P4.x */
    ctx.stub_pid          = GetCurrentProcessId();
    ctx.LogFn             = WriteLogFile;
    ctx.SetHotRevertFn    = AntiRE_Handles_SetHotRevert;
    ctx.SetD2PidFn        = AntiRE_Handles_SetD2Pid;
    ctx.CloseLoadingScreenFn = Stub_CloseLoadingScreen;
    ctx.SetLoadingTextFn  = Stub_UpdateLoadingText;
    ctx.stub_build_ver    = STUB_VER;
    ctx.payload_build_ver = login->payload_version;

    /* Copy login result into ctx.  These will be SecureZeroMemory'd in `login`
     * after PayloadMain returns, so the only live copy survives inside the
     * payload's identity cache (Payload_GetSessionId etc.). */
    {
        size_t i;
        for (i = 0; i < (PAYLOAD_CTX_USERNAME_CCH - 1) && login->username[i]; i++)
            ctx.username[i] = login->username[i];
        ctx.username[i] = 0;
    }
    /* P3.8 — propagar session_id + hwid para o payload (antire reusa). */
    strncpy_s(ctx.session_id, sizeof(ctx.session_id), login->session_id, _TRUNCATE);
    strncpy_s(ctx.hwid,       sizeof(ctx.hwid),       login->hwid,       _TRUNCATE);
    /* aes_key / hmac_key NUNCA propagam para o payload — consumidos só no stub. */

    WriteLogFile("Stub: calling PayloadMain");
    rc = pPayloadMain(&ctx);
    {
        char b[64];
        wsprintfA(b, "Stub: PayloadMain returned %d", rc);
        WriteLogFile(b);
    }

    /* Zero ctx — username might be sensitive, others were zero anyway. */
    SecureZeroMemory(&ctx, sizeof(ctx));

    /* FreeLibrary so the payload's DllMain(DLL_PROCESS_DETACH) runs and
     * the OS reclaims the mapping.  In the Phase 4 manual-map path this
     * is replaced with NtUnmapViewOfSection. */
    FreeLibrary(hPayload);

done:
    MUTATE_END
    return rc;
}

/* ── wWinMain ──────────────────────────────────────────────────────────────
 * The new entry point.  When this TU replaces loader.c in build_stub.bat,
 * this is what the linker uses (via /ENTRY:wWinMainCRTStartup).
 *
 * For Phase 1 (b.bat unchanged) this file is NOT compiled into the
 * legacy LOADERxxx.exe.  loader.c remains the active entry. */
int WINAPI wWinMain(HINSTANCE hI, HINSTANCE hP, LPWSTR lC, int nS) {
    UNREFERENCED_PARAMETER(hI);
    UNREFERENCED_PARAMETER(hP);
    UNREFERENCED_PARAMETER(lC);
    UNREFERENCED_PARAMETER(nS);

    MUTATE_START

    /* 1. Mitigations — apply BEFORE anything else loads/decodes. */
    Stub_ApplyMitigationPolicies();

    /* 2. Deferred log buffer — must be first call. */
    DbgBuf_Init();

    /* 2.1 Inicializa SSNs + gadget syscall;ret (P5.1).  Sem isso os stubs
     * `jmp QWORD PTR [g_SyscallGadgetVA]` em syscalls_asm.asm crasham. */
    InitSyscallNumbers();

    /* 2.1a Resolve system calls */

    /* 2.2 AntiRE 2.0 handle watcher (P6.2): protege Stub.exe desde o início,
     * antes mesmo da UI de login.  d2_pid é setado depois pelo payload via
     * AntiRE_Handles_SetD2Pid quando attach completar. */
    AntiRE_Handles_Start(GetCurrentProcessId());

    /* 3. Single-instance mutex. */
    WCHAR mutexName[64];
    Stub_BuildMutexName(mutexName);
    HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        /* TerminateProcess: avoid DllMain(DETACH) deadlocks in winhttp /
         * d3d12 / dxgi background threads (same rationale as legacy
         * loader.c). */
        TerminateProcess(GetCurrentProcess(), 0);
    }

    /* 4. SecureBoot gate. */
    InitializeChecks();
    if (SecureRead(&g_checks.secureboot)) {
        ShowCheckUI();
        goto _wWinMain_end;
    }

    /* 5. PEB spoof. */
    Stub_SpoofProcessName();

    /* 6. Login. */
    g_hCloseLoadingEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hLoadingDestroyedEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    StubLoginResult login = {0};
    if (!Stub_RunLoginPhase(&login)) {
        WriteLogFile("Stub: login cancelled / failed");
        goto _wWinMain_end;
    }

    /* Version validation gate */
    #if STUB_VER > 0
    if (STUB_VER < login.min_stub_version) {
        WriteLogFile("Stub: Loader version is too old. Update required.");
        MessageBoxW(NULL,
                    L"O seu loader está desatualizado. Por favor, baixe a nova versão no site.",
                    L"Atualização Obrigatória",
                    MB_ICONERROR);
        goto _wWinMain_end;
    }
    #endif

    /* 7. Resolve & run payload (Phase 2 LoadLibrary path; replaced in
     *    Phase 3-4 by transport+crypto+mapper). */
    /* STUB_PAYLOAD_RESOLVE: marker comment for Phase 3/4 to find the block. */
    struct PayloadThreadArgs {
        StubLoginResult* login;
        int rc;
    } pArgs = { &login, -1 };

    DWORD WINAPI PayloadRunner(LPVOID lpParam); // defined below to avoid lambda

    HANDLE hThread = CreateThread(NULL, 0, PayloadRunner, &pArgs, 0, NULL);
    if (hThread) {
        Stub_RenderLoadingPhase();
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        pArgs.rc = Stub_LoadAndRunPayload(&login);
        Stub_CloseLoadingScreen();
    }
    int rc = pArgs.rc;
    (void)rc;  /* return code reserved for future error UI */

    /* 8. Wipe sensitive material in `login` regardless of payload result. */
    SecureZeroMemory(&login, sizeof(login));

_wWinMain_end:
    AntiRE_Stop();
    AntiRE_Handles_Stop();

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
    if (g_hCloseLoadingEvent) CloseHandle(g_hCloseLoadingEvent);
    if (g_hLoadingDestroyedEvent) CloseHandle(g_hLoadingDestroyedEvent);
    DbgBuf_Free();
    MUTATE_END
    return 0;
}

DWORD WINAPI PayloadRunner(LPVOID lpParam) {
    struct PayloadThreadArgs {
        StubLoginResult* login;
        int rc;
    } *pArgs = lpParam;
    
    pArgs->rc = Stub_LoadAndRunPayload(pArgs->login);
    Stub_CloseLoadingScreen(); /* ensure loading screen is closed if failed early */
    return 0;
}
