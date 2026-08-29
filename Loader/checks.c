
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "ThemidaSDK.h"
#include "checks.h"
#include "command.h"
#include "XorStr.h"
#include "xor_strings.h"   /* ENC_reg_hvci, ENC_reg_secureboot, ENC_reg_ci_config, DXOR_REGKEY */
#include "Overlay.h"
#include "syscalls.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>

SYSTEM_CHECKS g_checks = {0};
typedef NTSTATUS(WINAPI*tNtQSI)(ULONG,PVOID,ULONG,PULONG);

#ifdef SERAPH_BUILD_TBH
static BOOL IsWindows11OrGreater(void) {
    HKEY hKey;
    char buildStr[32] = {0};
    DWORD sz = sizeof(buildStr);
    BOOL isWin11 = FALSE;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (LPBYTE)buildStr, &sz) == ERROR_SUCCESS) {
            int build = atoi(buildStr);
            if (build >= 22000) {
                isWin11 = TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return isWin11;
}
#endif

#pragma optimize("", off)
void InitializeChecks(){
    MUTATE_START
    
    /* Inicializa as variáveis seguras com FALSE para evitar lixo de pilha ou estado inválido */
    SecureWrite(&g_checks.hypervisor, FALSE);
    SecureWrite(&g_checks.secureboot, FALSE);
#ifdef SERAPH_BUILD_TBH
    SecureWrite(&g_checks.blocklist, FALSE);
#endif

    /* P1.1: Detect HVCI via SystemCodeIntegrityInformation direct syscall.
     * Evita consultas diretas a chaves de registro administrativas no DeviceGuard. */
    typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } SYSTEM_CODEINTEGRITY_INFORMATION;
    
    SYSTEM_CODEINTEGRITY_INFORMATION ci = {0};
    ci.Length = sizeof(ci);
    ULONG retLen = 0;
    NTSTATUS st = SysNtQuerySystemInformation(103 /* SystemCodeIntegrityInformation */, &ci, sizeof(ci), &retLen);
    if (NT_SUCCESS(st)) {
        if (ci.CodeIntegrityOptions & 0x400 /* CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED */) {
            SecureWrite(&g_checks.hypervisor, TRUE);
        }
    } else {
        /* Fallback silencioso de registro se a syscall falhar */
        HKEY hK; DWORD vS=0, cD=4;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,DXOR_A(ENC_reg_hvci),0,KEY_READ,&hK)==ERROR_SUCCESS){
            if(RegQueryValueExA(hK,"Enabled",NULL,NULL,(LPBYTE)&vS,&cD)==ERROR_SUCCESS&&vS==1) {
                SecureWrite(&g_checks.hypervisor, TRUE);
            }
            RegCloseKey(hK);
        }
    }
    
    /* P1.2: Detect SecureBoot via NVRAM environment variables.
     * GetFirmwareEnvironmentVariableW acessa a NVRAM diretamente e nao deixa pegada de leitura em chaves HKLM sensiveis. */
    BYTE sbVal = 0;
    DWORD retBytes = GetFirmwareEnvironmentVariableW(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &sbVal, 1);
    if (retBytes > 0 && sbVal == 1) {
        SecureWrite(&g_checks.secureboot, TRUE);
    } else {
        /* Fallback silencioso se a chamada de NVRAM falhar */
        HKEY hSB; DWORD sbValReg=0, sbSize=4;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,DXOR_A(ENC_reg_secureboot),0,KEY_READ,&hSB)==ERROR_SUCCESS){
            if(RegQueryValueExA(hSB,"UEFISecureBootEnabled",NULL,NULL,(LPBYTE)&sbValReg,&sbSize)==ERROR_SUCCESS&&sbValReg==1) {
                SecureWrite(&g_checks.secureboot, TRUE);
            }
            RegCloseKey(hSB);
        }
    }

#ifdef SERAPH_BUILD_TBH
    /* Microsoft Vulnerable Driver Blocklist detection (Win11 only) */
    SecureWrite(&g_checks.blocklist, FALSE);
    if (IsWindows11OrGreater()) {
        HKEY hBL; DWORD blVal=1, blSize=4;
        SecureWrite(&g_checks.blocklist, TRUE); // Enabled by default on Win11
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DXOR_A(ENC_reg_ci_config), 0, KEY_READ, &hBL) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hBL, "VulnerableDriverBlocklistEnable", NULL, NULL, (LPBYTE)&blVal, &blSize) == ERROR_SUCCESS) {
                if (blVal == 0) {
                    SecureWrite(&g_checks.blocklist, FALSE); // Explicitly disabled
                }
            }
            RegCloseKey(hBL);
        }
    }
#endif
    MUTATE_END
}
#pragma optimize("", on)

#ifdef SERAPH_BUILD_TBH
static void DisableHVCI(void) {
    HKEY hKey;
    DWORD val = 0;
    // 1. Disable HVCI scenario
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, DXOR_A(ENC_reg_hvci), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "Enabled", 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    // 2. Disable VBS
    { char _vbs[72];
      static const char _vbsE[]="SYSTEM\\CurrentControlSet\\Control\\DeviceGuard";
      for(int i=0;_vbsE[i];i++)_vbs[i]=(char)(((unsigned char)_vbsE[i])^0x5E^0x5E);_vbs[sizeof(_vbsE)-1]=0; /* self-cancel: no actual encode here, use literal decode */
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableVirtualizationBasedSecurity", 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    // 3. Disable Microsoft Vulnerable Driver Blocklist
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, DXOR_A(ENC_reg_ci_config), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "VulnerableDriverBlocklistEnable", 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

static void DoReboot(void) {
    HANDLE hTok; TOKEN_PRIVILEGES tp; LUID luid;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
        if (LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hTok);
    }
    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_FLAG_PLANNED);
}
#endif

LRESULT CALLBACK CheckWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE:
#ifdef SERAPH_BUILD_TBH
        /* All active checks block driver loading */
        Overlay_SetSystemCheckResults(SecureRead(&g_checks.hypervisor), SecureRead(&g_checks.secureboot), SecureRead(&g_checks.blocklist));
#else
        /* Both HVCI and SecureBoot block driver loading */
        Overlay_SetSystemCheckResults(FALSE, !SecureRead(&g_checks.secureboot), SecureRead(&g_checks.hypervisor));
#endif
        break;
    case WM_LBUTTONDOWN:
        Overlay_UpdateMouse(LOWORD(l), HIWORD(l), TRUE);
#ifdef SERAPH_BUILD_TBH
        if (LOWORD(l) >= 18 && LOWORD(l) <= 282 && HIWORD(l) >= 272 && HIWORD(l) <= 312) {
            if (!SecureRead(&g_checks.hypervisor) && !SecureRead(&g_checks.secureboot) && !SecureRead(&g_checks.blocklist)) {
                Overlay_Stop();
            } else {
                // Apply registry changes
                DisableHVCI();
                
                // Show message and reboot normally (like original Seraph, no automatic BIOS UEFI boot)
                /* XOR-decoded title "Seraph System Setup" — P1: elimina assinatura estática trivial.
                 * Decode: each byte = enc[i] ^ 0x73  */
                static const unsigned char _sss[] = {
                    0x20,0x16,0x00,0x07,0x1B,0x17,0x08,0x73,
                    0x20,0x06,0x1D,0x1F,0x17,0x14,0x73,0x20,
                    0x17,0x03,0x1C,0x07,0x00,0x00
                };
                wchar_t _sssW[22];
                for(int _i=0;_i<21;_i++) _sssW[_i]=(wchar_t)(((unsigned char)_sss[_i])^0x73);
                _sssW[21]=0;
                MessageBoxW(NULL,
                    L"As configura\u00e7\u00f5es de compatibilidade (HVCI, VBS e Blocklist) foram aplicadas no registro.\n\n"
                    L"Caso o Secure Boot esteja ativo, lembre-se de desativ\u00e1-lo manualmente nas configura\u00e7\u00f5es da BIOS se o driver falhar ao carregar.\n\n"
                    L"O computador ser\u00e1 reiniciado agora para aplicar as altera\u00e7\u00f5es.",
                    _sssW, MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
                DoReboot();
            }
        }
#else
        if (LOWORD(l) >= 18 && LOWORD(l) <= 282 && HIWORD(l) >= 222 && HIWORD(l) <= 262) {
            if (!SecureRead(&g_checks.hypervisor) && !SecureRead(&g_checks.secureboot)) {
                Overlay_Stop();
            } else if (SecureRead(&g_checks.hypervisor)) {
                MessageBoxW(NULL,
                    L"HVCI (Memory Integrity / VBS) est\u00e1 ativo.\n\n"
                    L"O driver n\u00e3o consegue carregar com HVCI ativo.\n"
                    L"Desative o Memory Integrity em:\n"
                    L"Seguran\u00e7a do Windows \u2192 Seguran\u00e7a do Dispositivo \u2192\n"
                    L"Isolamento do N\u00facleo \u2192 Memory Integrity: OFF\n"
                    L"Reinicie o PC ap\u00f3s desativar.",
                    L"System Check", MB_OK|MB_ICONWARNING|MB_TOPMOST);
            } else {
                MessageBoxW(NULL,
                    L"Secure Boot est\u00e1 ativo.\n\n"
                    L"O driver n\u00e3o consegue carregar com Secure Boot ativo.\n"
                    L"Desative o Secure Boot na BIOS/UEFI do seu PC e\n"
                    L"reinicie.",
                    L"System Check", MB_OK|MB_ICONWARNING|MB_TOPMOST);
            }
        }
#endif
        break;
    case WM_LBUTTONUP:  Overlay_UpdateMouse(LOWORD(l), HIWORD(l), FALSE); break;
    case WM_MOUSEMOVE:  Overlay_UpdateMouse(LOWORD(l), HIWORD(l), !!(w & MK_LBUTTON)); break;
    case WM_DESTROY:    PostQuitMessage(0); break;
    }
    return DefWindowProc(h, m, w, l);
}

void ShowCheckUI(void){
    /* A-8: Randomize class and window names per-run to avoid static "SeraphCheck"/"System Check"
       signatures rastreáveis via EnumWindows. Uses same LCG as ShowMainGUI. */
    WCHAR szCls[32], szTtl[32];
    /* P9: seed neutro — 0xC0DE5AFE1337 era assinável como magic constant */
    {ULONGLONG _s=(ULONGLONG)GetTickCount64()^(ULONGLONG)GetCurrentProcessId()^0x7E3F9B21A4DULL;
    for(int _i=0;_i<31;_i++){_s=_s*6364136223846793005ULL+1442695040888963407ULL;szCls[_i]=L'a'+(WCHAR)((_s>>33)%26);_s=_s*6364136223846793005ULL+1442695040888963407ULL;szTtl[_i]=L'a'+(WCHAR)((_s>>33)%26);}szCls[31]=0;szTtl[31]=0;}

    WNDCLASSEXW w={0};w.cbSize=sizeof(w);w.lpfnWndProc=CheckWndProc;w.hInstance=GetModuleHandleW(NULL);w.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);w.lpszClassName=szCls;
    RegisterClassExW(&w);
#ifdef SERAPH_BUILD_TBH
    int x=(GetSystemMetrics(0)-300)/2,y=(GetSystemMetrics(1)-330)/2;
    HWND h=CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW,szCls,szTtl,WS_POPUP|WS_VISIBLE,x,y,300,330,NULL,NULL,w.hInstance,NULL);
#else
    int x=(GetSystemMetrics(0)-300)/2,y=(GetSystemMetrics(1)-278)/2;
    HWND h=CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW,szCls,szTtl,WS_POPUP|WS_VISIBLE,x,y,300,278,NULL,NULL,w.hInstance,NULL);
#endif
    if(!h) return;
    BOOL oc=Overlay_Create(h);
    if(!oc){DestroyWindow(h);return;}
#ifdef SERAPH_BUILD_TBH
    Overlay_SetSystemCheckResults(SecureRead(&g_checks.hypervisor), SecureRead(&g_checks.secureboot), SecureRead(&g_checks.blocklist));
#else
    Overlay_SetSystemCheckResults(FALSE, !SecureRead(&g_checks.secureboot), SecureRead(&g_checks.hypervisor));
#endif
    MSG m;while(Overlay_IsRunning()){if(PeekMessage(&m,NULL,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessage(&m);if(m.message==WM_QUIT)break;}Overlay_RenderSystemCheck();SeraphSleep(10);}
    Overlay_Destroy();DestroyWindow(h);
}

