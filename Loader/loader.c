
/* loader.c -- Seraph V1 entry point (BYOVD architecture) */
#include "Loader.h"
#include "Overlay.h"
#include "checks.h"
#include "gui.h"
#include "debug.h"
#include "evasion_user.h"
#include "debug_buffer.h"
#include "seraph_handle_bucket.h"
#include "seraph_ptr_crypt.h"
#include "xor_strings.h"
#include "seraph_secure_val.h"
#include "ThemidaSDK.h"
#include "silent_aim.h"
#include "infinite_ammo.h"
#include "no_recoil.h"
#include <windows.h>
#include "syscalls.h"

void WriteLog(const char* msg){ (void)msg; }

#pragma optimize("", off)
int WINAPI wWinMain(HINSTANCE hI, HINSTANCE hP, LPWSTR lC, int nS){
    /* MUTATE protects the entry-point: mutex single-instance check, derive
     * volume-based UUID, gate on hypervisor/secureboot. VM is too heavy here
     * because wWinMain pulls in the whole GUI loop indirectly via ShowMainGUI. */
    MUTATE_START
    UNREFERENCED_PARAMETER(hI); UNREFERENCED_PARAMETER(hP);
    UNREFERENCED_PARAMETER(lC); UNREFERENCED_PARAMETER(nS);

    /* Initialize deferred log buffer, custom HandleBucket, and ARX Ptr Encryption */
    DbgBuf_Init();
    SeraphHB_Init();
    SeraphPtr_Init();
    InitSyscallNumbers();

    /* NOTE: UeErasePEHeader() is intentionally NOT called here.
     * Themida's VM protection adds its own TLS callbacks/variables.
     * Zeroing the PE header (incl. TLS DataDirectory entry) at process
     * startup prevents Windows from initialising TLS for any subsequently
     * created thread — CreateThread returns NULL.
     * UeErasePEHeader() is called inside ShowMainGUI() immediately after
     * AUTH_SUCCESS is confirmed, before the BYOVD thread is spawned. */

    /* A-7: Single-instance mutex with fully randomized UUID — all 5 fields derived
     * from vol serial via cascaded hash. No fixed substring in the binary. */
    DWORD volSerial = 0;
    GetVolumeInformationW(DXOR_W(ENC_drive_root), NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    /* Derive four independent 32-bit values via LCG chain (Knuth constants) */
    DWORD h1 = volSerial;
    DWORD h2 = (h1 * 0x9E3779B9u) ^ 0x3C4A7F12u; h2 = (h2 << 13) | (h2 >> 19);
    DWORD h3 = (h2 * 0x9E3779B9u) ^ 0xB1E2D4C8u; h3 = (h3 <<  7) | (h3 >> 25);
    DWORD h4 = (h3 * 0x9E3779B9u) ^ 0x7A4F2E9Bu; h4 = (h4 << 17) | (h4 >> 15);

    /* Decrypt L"Local\\WER_SharedMem_Mutex_%08X" (key 0xA5) */
    static const USHORT _mtx[] = {0xE9,0xCA,0xC6,0xC4,0xC9,0xF9,0xF2,0xE0,0xF7,0xFA,0xF6,0xCD,0xC4,0xD7,0xC0,0xC1,0xE8,0xC0,0xC8,0xFA,0xE8,0xD0,0xD1,0xC0,0xDD,0xFA,0x80,0x95,0x9D,0xFD};
    WCHAR _mtxW[31]; for(int _i=0;_i<30;_i++) _mtxW[_i]=(WCHAR)(_mtx[_i]^0xA5u); _mtxW[30]=0;

    WCHAR mutexName[64];
    wsprintfW(mutexName, _mtxW,
              (h1 ^ h2 ^ h3 ^ h4) ^ 0xD8A3F2C5u);
    HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        SysNtClose(hMutex);
        /* Use TerminateProcess instead of return 0 / ExitProcess:
         * winhttp.dll / d3d12.dll / dxgi.dll create background threads in their
         * DllMain(DLL_PROCESS_ATTACH). exit() and ExitProcess both invoke
         * DllMain(DLL_PROCESS_DETACH) for each DLL, which may deadlock waiting
         * for those threads — leaving the process frozen in task manager forever.
         * TerminateProcess skips ALL DLL cleanup and kills the process immediately.
         * Safe here: the second instance has opened no files, no GPU resources,
         * and no application threads — nothing needs orderly cleanup. */
        SysNtTerminateProcess(SERAPH_CURRENT_PROCESS, 0);
    }
    INT32 hMutexObf = SeraphHB_Insert(hMutex);

    InitializeChecks();
    /* Block on HVCI, SecureBoot, or Driver Blocklist — prevent driver loading */
#ifdef SERAPH_BUILD_TBH
    if(SecureRead(&g_checks.hypervisor) || SecureRead(&g_checks.secureboot) || SecureRead(&g_checks.blocklist)){
#else
    if(SecureRead(&g_checks.hypervisor) || SecureRead(&g_checks.secureboot)){
#endif
        ShowCheckUI();
        goto _wWinMain_end;
    }
    ShowMainGUI();
    /* Release mutex before process exits */
    HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
    if(h){ ReleaseMutex(h); SysNtClose(h); SeraphHB_Remove(hMutexObf); }
    /* Free ring buffer — no file created on clean exit */
    DbgBuf_Free();
_wWinMain_end:
    MUTATE_END
    SysNtTerminateProcess(SERAPH_CURRENT_PROCESS, 0);
    return 0;
}
#pragma optimize("", on)

