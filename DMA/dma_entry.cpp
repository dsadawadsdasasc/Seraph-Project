/*
 * dma_entry.cpp  --  DMA Loader Shell (Casca) entry point.
 * Performs single-instance check, UAC check, MemProcFS initialization,
 * displays a native Win32 login dialog, validates with KeyAuth,
 * loads the payload DLL in memory, and starts the cheat.
 */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <winhttp.h>
#include <fstream>

#include "ThemidaSDK.h"
#include "Resource.h"
extern "C" {
#include "keyauth.h"
#include "xor_strings.h"
}
#include "dma_pe_loader.h"
#include "dma_dll_loader.h"
#include "seraph_handle_bucket.h"
#include "seraph_ptr_crypt.h"

// Forward declaration of KeyAuth username global (needed for keyauth)
extern wchar_t g_kaUsername[64];

static wchar_t g_LicenseKey[256] = {0};

static BOOL IsRunningAsAdmin(void) {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te = {0};
        DWORD cb = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, cb, &cb))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated;
}

// Dialog Procedure for KeyAuth Login
INT_PTR CALLBACK LoginDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch (uMsg) {
        case WM_INITDIALOG:
            SetDlgItemTextW(hwndDlg, IDC_KEY_EDIT, L"");
            SetDlgItemTextW(hwndDlg, IDC_STATUS_TEXT, L"Aguardando login...");
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                GetDlgItemTextW(hwndDlg, IDC_KEY_EDIT, g_LicenseKey, 256);
                if (wcslen(g_LicenseKey) == 0) {
                    SetDlgItemTextW(hwndDlg, IDC_STATUS_TEXT, L"Digite uma chave valida!");
                    return TRUE;
                }

                SetDlgItemTextW(hwndDlg, IDC_STATUS_TEXT, L"Autenticando...");
                EnableWindow(GetDlgItem(hwndDlg, IDOK), FALSE);
                EnableWindow(GetDlgItem(hwndDlg, IDC_KEY_EDIT), FALSE);
                UpdateWindow(hwndDlg);

                // Run KeyAuth validation
                wchar_t errMsg[256] = {0};
                KEYAUTH_RESULT res = KeyAuthValidate(g_LicenseKey, errMsg, 256);
                if (res == KEYAUTH_SUCCESS) {
                    SetDlgItemTextW(hwndDlg, IDC_STATUS_TEXT, L"Sucesso!");
                    EndDialog(hwndDlg, IDOK);
                } else {
                    if (wcslen(errMsg) == 0) {
                        swprintf_s(errMsg, 256, L"Erro de autenticacao: %d", res);
                    }
                    SetDlgItemTextW(hwndDlg, IDC_STATUS_TEXT, errMsg);
                    EnableWindow(GetDlgItem(hwndDlg, IDOK), TRUE);
                    EnableWindow(GetDlgItem(hwndDlg, IDC_KEY_EDIT), TRUE);
                }
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hwndDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

typedef HANDLE (*PFN_StartCheat)(HINSTANCE);

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    VM_START

    // Initialize security wrappers
    SeraphHB_Init();
    SeraphPtr_Init();

    MUTATE_START
    if (!IsRunningAsAdmin()) {
        MessageBoxW(NULL,
            L"Execute o LOADER como Administrador.\n"
            L"(clique direito -> Executar como administrador)",
            L"Seraph DMA",
            MB_ICONWARNING | MB_OK);
        VM_END
        return 1;
    }

    // Mutex check for single instance
    DWORD volSerial = 0;
    GetVolumeInformationW(L"C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    DWORD h1 = volSerial ^ 0xDDA4C3B1u;
    DWORD h2 = (h1 * 0x9E3779B9u) ^ 0x5F2E8A7Du; h2 = (h2 << 13) | (h2 >> 19);
    DWORD h3 = (h2 * 0x9E3779B9u) ^ 0xC8B4E2F1u; h3 = (h3 <<  7) | (h3 >> 25);
    DWORD h4 = (h3 * 0x9E3779B9u) ^ 0x9D3A5C6Eu; h4 = (h4 << 17) | (h4 >> 15);
    WCHAR mutexName[64];
    wsprintfW(mutexName, L"Global\\{%08X-%04X-%04X-%04X-%08X%04X}",
              h1, (WORD)(h2>>16), (WORD)(h2&0xFFFF),
              (WORD)(h3>>16), h4, (WORD)(h3&0xFFFF));

    HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        MessageBoxW(NULL,
            L"Seraph DMA ja esta em execucao.\n"
            L"Feche a outra instancia antes de abrir de novo.",
            L"Seraph DMA", MB_ICONINFORMATION | MB_OK);
        VM_END
        return 0;
    }
    INT32 hMutexObf = SeraphHB_Insert(hMutex);
    MUTATE_END

    // Initialize DMA libraries
    if (!DmaLoader_Init(hInst)) {
        DWORD err = DmaLoader_GetLastError();
        wchar_t msg[512];
        swprintf_s(msg, 512, L"Falha ao iniciar o motor DMA (Erro: %lu).\nVerifique se as bibliotecas estao completas.", err);
        MessageBoxW(NULL, msg, L"Seraph DMA", MB_ICONERROR | MB_OK);
        
        HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
        if (h) { CloseHandle(h); SeraphHB_Remove(hMutexObf); }
        VM_END
        return 1;
    }
    SetDllDirectoryW(NULL);

    // Show native Login Dialog
    INT_PTR dlgRes = DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_LOGIN_DIALOG), NULL, LoginDlgProc, 0);
    if (dlgRes != IDOK) {
        DmaLoader_Cleanup();
        HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
        if (h) { CloseHandle(h); SeraphHB_Remove(hMutexObf); }
        VM_END
        return 0;
    }

    // Try to load the payload
    std::vector<BYTE> peBuffer;
    bool loaded = false;

    // 1. Try local payload.dll (for development/debug)
    std::ifstream dllFile("payload.dll", std::ios::binary | std::ios::ate);
    if (dllFile.is_open()) {
        size_t sz = dllFile.tellg();
        peBuffer.resize(sz);
        dllFile.seekg(0, std::ios::beg);
        dllFile.read(reinterpret_cast<char*>(peBuffer.data()), sz);
        dllFile.close();
        loaded = true;
    }

    // 2. Download payload.bin from GitHub RAW if not loaded locally
    if (!loaded) {
        /* Stack-constructed wide strings to conceal host & path from static inspection without typos */
        wchar_t host[64] = {};
        static const wchar_t rawH[] = { L'r',L'a',L'w',L'.',L'g',L'i',L't',L'h',L'u',L'b',L'u',L's',L'e',L'r',L'c',L'o',L'n',L't',L'e',L'n',L't',L'.',L'c',L'o',L'm',0 };
        for (int i = 0; rawH[i]; i++) host[i] = rawH[i];

        wchar_t path[128] = {};
        static const wchar_t rawP[] = { L'/',L'd',L's',L'a',L'd',L'a',L'w',L'a',L'd',L's',L'd',L'a',L's',L'a',L's',L'c',L'/',L'h',L'j',L'i',L'k',L'b',L'd',L'f',L'b',L'h',L'u',L's',L'd',L'f',L'b',L'h',L's',L'd',L'f',L'g',L'/',L'm',L'a',L'i',L'n',L'/',L'p',L'a',L'y',L'l',L'o',L'a',L'd',L'.',L'b',L'i',L'n',0 };
        for (int i = 0; rawP[i]; i++) path[i] = rawP[i];

        HINTERNET hSession = WinHttpOpen(L"SeraphDMA/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConnect) {
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (hRequest) {
                    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                        WinHttpReceiveResponse(hRequest, NULL)) {
                        
                        DWORD statusCode = 0;
                        DWORD statusCodeSize = sizeof(statusCode);
                        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
                        
                        if (statusCode == 200) {
                            DWORD bytesAvailable = 0;
                            while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
                                std::vector<BYTE> chunk(bytesAvailable);
                                DWORD bytesRead = 0;
                                if (WinHttpReadData(hRequest, chunk.data(), bytesAvailable, &bytesRead) && bytesRead > 0) {
                                    peBuffer.insert(peBuffer.end(), chunk.begin(), chunk.begin() + bytesRead);
                                }
                            }
                            if (!peBuffer.empty()) {
                                // Decrypt with XOR key (0xAA)
                                for (size_t i = 0; i < peBuffer.size(); i++) {
                                    peBuffer[i] ^= 0xAA;
                                }
                                loaded = true;
                            }
                        }
                    }
                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
        }
    }

    // 3. Fallback to local payload.bin if download failed
    if (!loaded) {
        std::ifstream binFile("payload.bin", std::ios::binary | std::ios::ate);
        if (binFile.is_open()) {
            size_t sz = binFile.tellg();
            peBuffer.resize(sz);
            binFile.seekg(0, std::ios::beg);
            binFile.read(reinterpret_cast<char*>(peBuffer.data()), sz);
            binFile.close();
            
            // Decrypt with XOR key (0xAA)
            for (size_t i = 0; i < peBuffer.size(); i++) {
                peBuffer[i] ^= 0xAA;
            }
            loaded = true;
        }
    }

    if (!loaded) {
        MessageBoxW(NULL,
            L"Nao foi possivel carregar o payload (payload.dll ou payload.bin ausentes).\n"
            L"Verifique se os arquivos de execucao estao completos.",
            L"Seraph DMA", MB_ICONERROR | MB_OK);
        DmaLoader_Cleanup();
        HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
        if (h) { CloseHandle(h); SeraphHB_Remove(hMutexObf); }
        VM_END
        return 1;
    }

    // Reflective PE loading
    HMEMORYMODULE hModule = DmaLoadPE(peBuffer.data(), peBuffer.size());
    if (!hModule) {
        MessageBoxW(NULL, L"Falha ao mapear o payload na memoria.", L"Seraph DMA", MB_ICONERROR | MB_OK);
        DmaLoader_Cleanup();
        HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
        if (h) { CloseHandle(h); SeraphHB_Remove(hMutexObf); }
        VM_END
        return 1;
    }

    PFN_StartCheat StartCheat = (PFN_StartCheat)DmaGetPEProcAddress(hModule, "StartCheat");
    if (!StartCheat) {
        MessageBoxW(NULL, L"Assinatura do payload incorreta (export StartCheat nao encontrado).", L"Seraph DMA", MB_ICONERROR | MB_OK);
        DmaFreePE(hModule);
        DmaLoader_Cleanup();
        HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
        if (h) { CloseHandle(h); SeraphHB_Remove(hMutexObf); }
        VM_END
        return 1;
    }

    // Run the cheat (launches in its own thread inside the DLL)
    HANDLE hCheatThread = StartCheat(hInst);
    if (hCheatThread) {
        WaitForSingleObject(hCheatThread, INFINITE);
        CloseHandle(hCheatThread);
    }

    // Clean up all resources when the cheat exits
    DmaFreePE(hModule);
    DmaLoader_Cleanup();
    HANDLE h = (HANDLE)SeraphHB_Lookup(hMutexObf);
    if (h) { ReleaseMutex(h); CloseHandle(h); SeraphHB_Remove(hMutexObf); }

    VM_END
    return 0;
}

extern "C" {
    NTSTATUS SysNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
        (void)Alertable;
        if (DelayInterval) {
            LONGLONG ms = -DelayInterval->QuadPart / 10000;
            Sleep((DWORD)ms);
        }
        return 0;
    }

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
}

