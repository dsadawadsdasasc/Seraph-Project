/*
 * dma_antire_stub.cpp  --  Active Ring 3 Anti-Debugging / Copy Protection for DMA.
 *
 * Runs on the operator's PC to detect common debuggers and reverse engineering tools.
 */

#include "antire.h"
#include <windows.h>
#include <winternl.h>
#include <ctype.h>

static volatile BOOL s_running = FALSE;
static HANDLE        s_thread  = NULL;

// Hide thread from debugger (ThreadHideFromDebugger = 0x11)
typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

static void HideCurrentThread(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        pfnNtSetInformationThread NtSetInformationThread = 
            (pfnNtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (NtSetInformationThread) {
            NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
        }
    }
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    char title[256];
    if (GetWindowTextA(hwnd, title, sizeof(title)) > 0) {
        const char* badKeywords[] = {
            "x64dbg", "x32dbg", "cheat engine", "ida pro", "process hacker", "process explorer", "hxd", "wireshark", "dnspy"
        };
        // Convert title to lowercase
        for (int i = 0; title[i]; i++) {
            title[i] = (char)tolower(title[i]);
        }
        for (int i = 0; i < sizeof(badKeywords) / sizeof(badKeywords[0]); i++) {
            if (strstr(title, badKeywords[i])) {
                *(BOOL*)lParam = TRUE;
                return FALSE; // stop enumeration
            }
        }
    }
    return TRUE; // continue enumeration
}

static DWORD WINAPI AntiRE_Worker(LPVOID lpParam) {
    (void)lpParam;
    HideCurrentThread();

    while (s_running) {
        // 1. IsDebuggerPresent
        if (IsDebuggerPresent()) {
            ExitProcess(0xBAAD0001);
        }

        // 2. CheckRemoteDebuggerPresent
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
            ExitProcess(0xBAAD0002);
        }

        // 3. Scan for common debugger/analysis windows (robust substring matching)
        BOOL foundBadWindow = FALSE;
        EnumWindows(EnumWindowsProc, (LPARAM)&foundBadWindow);
        if (foundBadWindow) {
            ExitProcess(0xBAAD0003);
        }

        Sleep(1000);
    }
    return 0;
}

extern "C" void AntiRE_Start(void) {
    if (s_running) return;
    s_running = TRUE;
    s_thread = CreateThread(NULL, 0, AntiRE_Worker, NULL, 0, NULL);
}

extern "C" void AntiRE_Stop(void) {
    s_running = FALSE;
    if (s_thread) {
        WaitForSingleObject(s_thread, 2000);
        CloseHandle(s_thread);
        s_thread = NULL;
    }
}
