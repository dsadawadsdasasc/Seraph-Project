/*
 * Standalone MemProcFS: vmm + leechcore + FTD3XX embedded in EXE (RCDATA).
 * Do NOT use SetDllDirectoryW — it breaks D2D/DWrite/D3D for the login UI.
 */

#include "ThemidaSDK.h"
#include "dma_dll_loader.h"
#include <delayimp.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

wchar_t g_dmaExtractDir[MAX_PATH] = {0};
wchar_t g_vmmDllPath    [MAX_PATH] = {0};
wchar_t g_leechDllPath  [MAX_PATH] = {0};
wchar_t g_ftdDllPath    [MAX_PATH] = {0};

static HMODULE g_hFtd   = NULL;
static HMODULE g_hLeech = NULL;
static HMODULE g_hVmm   = NULL;
static PVOID   g_dllDirCookie = NULL;
static BOOL    g_inited = FALSE;
static DWORD   g_lastErr = 0;

static const wchar_t *kCleanupFiles[] = {
    L"vmm.dll", L"leechcore.dll", L"FTD3XX.dll", nullptr
};

static const DWORD kMinResSize[] = { 300000, 100000, 500000 };

static UINT64 MachineHash(void) {
    MUTATE_START
    UINT64 h = 0xcbf29ce484222325ULL;
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        for (int i = 0; i < 4; i++) {
            h ^= (UINT8)((serial >> (i * 8)) & 0xFFu);
            h *= 0x100000001b3ULL;
        }
    }
    char comp[64] = {0};
    DWORD clen = sizeof(comp);
    if (GetComputerNameA(comp, &clen)) {
        for (DWORD i = 0; i < clen; i++) {
            h ^= (UINT8)comp[i];
            h *= 0x100000001b3ULL;
        }
    }
    if (h == 0) h = 0xfeedfacecafebabeULL;
    MUTATE_END
    return h;
}

static void ClearZoneIdentifier(const wchar_t *filePath) {
    if (!filePath || !filePath[0]) return;
    wchar_t ads[MAX_PATH + 32];
    wsprintfW(ads, L"%s:Zone.Identifier", filePath);
    DeleteFileW(ads);
}

static BOOL ResourceOk(HMODULE hMod, int resId, DWORD minSize) {
    HRSRC hr = FindResourceW(hMod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hr) return FALSE;
    return SizeofResource(hMod, hr) >= minSize;
}

static BOOL ExtractResource(HMODULE hMod, int resId, const wchar_t *outPath) {
    HRSRC hRsrc = FindResourceW(hMod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hRsrc) return FALSE;
    HGLOBAL hGlob = LoadResource(hMod, hRsrc);
    if (!hGlob) return FALSE;
    void *pData = LockResource(hGlob);
    DWORD dwSize = SizeofResource(hMod, hRsrc);
    if (!pData || !dwSize) return FALSE;

    HANDLE hFile = CreateFileW(outPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, pData, dwSize, &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != dwSize) return FALSE;
    ClearZoneIdentifier(outPath);
    return TRUE;
}

static void BuildExtractPath(const wchar_t *fileName, wchar_t *outPath, size_t cch) {
    wcscpy_s(outPath, cch, g_dmaExtractDir);
    wcscat_s(outPath, cch, L"\\");
    wcscat_s(outPath, cch, fileName);
}

static BOOL ExtractEmbedded(HMODULE hMod, int resId, const wchar_t *fileName, DWORD minSize) {
    if (!ResourceOk(hMod, resId, minSize)) return FALSE;

    wchar_t outPath[MAX_PATH];
    BuildExtractPath(fileName, outPath, MAX_PATH);

    HRSRC hr = FindResourceW(hMod, MAKEINTRESOURCEW(resId), RT_RCDATA);
    DWORD expected = SizeofResource(hMod, hr);
    WIN32_FILE_ATTRIBUTE_DATA fa = {0};
    if (GetFileAttributesExW(outPath, GetFileExInfoStandard, &fa) &&
        fa.nFileSizeLow == expected && fa.nFileSizeHigh == 0)
        return TRUE;

    return ExtractResource(hMod, resId, outPath);
}

static BOOL MakeExtractDir(const wchar_t *parentBase) {
    if (!parentBase || !parentBase[0]) return FALSE;
    UINT64 h = MachineHash();
    if (swprintf_s(g_dmaExtractDir, MAX_PATH, L"%s\\Seraph\\dma\\%016llx",
            parentBase, (unsigned long long)h) <= 0)
        return FALSE;
    int r = SHCreateDirectoryExW(NULL, g_dmaExtractDir, NULL);
    return r == ERROR_SUCCESS || r == ERROR_ALREADY_EXISTS;
}

static BOOL DmaLoader_ExtractAll(HMODULE hModule) {
    if (g_dmaExtractDir[0] != L'\0') return TRUE;
    if (!hModule) hModule = GetModuleHandleW(NULL);

    if (!ResourceOk(hModule, IDR_VMM_DLL, kMinResSize[2]) ||
        !ResourceOk(hModule, IDR_LEECHCORE_DLL, kMinResSize[1]) ||
        !ResourceOk(hModule, IDR_FTD3XX_DLL, kMinResSize[0])) {
        g_lastErr = ERROR_RESOURCE_DATA_NOT_FOUND;
        return FALSE;
    }

    wchar_t appData[MAX_PATH] = {0};
    wchar_t temp[MAX_PATH] = {0};
    BOOL haveDir = FALSE;

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData)))
        haveDir = MakeExtractDir(appData);
    if (!haveDir && GetTempPathW(MAX_PATH, temp) > 0)
        haveDir = MakeExtractDir(temp);

    if (!haveDir) {
        g_lastErr = GetLastError();
        return FALSE;
    }

    struct Item { int resId; const wchar_t *name; wchar_t *pathOut; DWORD minSz; } items[] = {
        { IDR_FTD3XX_DLL,    L"FTD3XX.dll",    g_ftdDllPath,   kMinResSize[0] },
        { IDR_LEECHCORE_DLL, L"leechcore.dll", g_leechDllPath, kMinResSize[1] },
        { IDR_VMM_DLL,       L"vmm.dll",       g_vmmDllPath,   kMinResSize[2] },
    };

    for (int i = 0; i < 3; i++) {
        if (!ExtractEmbedded(hModule, items[i].resId, items[i].name, items[i].minSz)) {
            g_lastErr = GetLastError();
            g_dmaExtractDir[0] = L'\0';
            return FALSE;
        }
        wcscpy_s(items[i].pathOut, MAX_PATH, g_dmaExtractDir);
        wcscat_s(items[i].pathOut, MAX_PATH, L"\\");
        wcscat_s(items[i].pathOut, MAX_PATH, items[i].name);
    }
    return TRUE;
}

static HMODULE LoadFromExtract(const wchar_t *fullPath) {
    HMODULE h = LoadLibraryExW(fullPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h)
        g_lastErr = GetLastError();
    return h;
}

static BOOL DmaLoader_Preload(void) {
    if (!g_ftdDllPath[0] || !g_leechDllPath[0] || !g_vmmDllPath[0])
        return FALSE;

    if (!g_hFtd)   g_hFtd   = LoadFromExtract(g_ftdDllPath);
    if (!g_hLeech) g_hLeech = LoadFromExtract(g_leechDllPath);
    if (!g_hVmm)   g_hVmm   = LoadFromExtract(g_vmmDllPath);

    return (g_hFtd && g_hLeech && g_hVmm) ? TRUE : FALSE;
}

void DmaLoader_EnsureSearchPath(void) {
    if (g_dmaExtractDir[0] == L'\0') return;

    /* Never SetDllDirectoryW — breaks D2D/DWrite for Overlay_Create. */
    if (!g_dllDirCookie) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        typedef BOOL (WINAPI *FnSetDefaultDllDirectories)(DWORD);
        typedef DLL_DIRECTORY_COOKIE (WINAPI *FnAddDllDirectory)(PCWSTR);
        auto pSet = k32 ? (FnSetDefaultDllDirectories)GetProcAddress(k32, "SetDefaultDllDirectories") : NULL;
        auto pAdd = k32 ? (FnAddDllDirectory)GetProcAddress(k32, "AddDllDirectory") : NULL;
        if (pSet)
            pSet(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        if (pAdd)
            g_dllDirCookie = pAdd(g_dmaExtractDir);
    }
}

static FARPROC WINAPI DmaDelayLoadHook(unsigned dliNotify, PDelayLoadInfo pdli) {
    if (dliNotify == dliNotePreLoadLibrary && pdli && pdli->szDll) {
        const char *dll = pdli->szDll;
        if (!_stricmp(dll, "vmm.dll") && g_hVmm)
            return (FARPROC)g_hVmm;
        if (!_stricmp(dll, "leechcore.dll") && g_hLeech)
            return (FARPROC)g_hLeech;
        if (!_stricmp(dll, "FTD3XX.dll") && g_hFtd)
            return (FARPROC)g_hFtd;

        wchar_t wname[64] = {0};
        wchar_t path[MAX_PATH];
        if (g_dmaExtractDir[0] &&
            MultiByteToWideChar(CP_ACP, 0, dll, -1, wname, 64) > 0) {
            BuildExtractPath(wname, path, MAX_PATH);
            HMODULE h = LoadFromExtract(path);
            if (h) return (FARPROC)h;
        }
    }
    return NULL;
}

extern "C" {
const PfnDliHook __pfnDliNotifyHook2 = DmaDelayLoadHook;
}

BOOL DmaLoader_Init(HMODULE hModule) {
    if (g_inited) return (g_hVmm && g_hLeech && g_hFtd);

    if (!DmaLoader_ExtractAll(hModule))
        return FALSE;

    DmaLoader_EnsureSearchPath();

    if (!DmaLoader_Preload())
        return FALSE;

    g_inited = TRUE;
    return TRUE;
}

DWORD DmaLoader_GetLastError(void) {
    return g_lastErr ? g_lastErr : GetLastError();
}

void DmaLoader_Cleanup(void) {
    if (g_dmaExtractDir[0] == L'\0') return;

    if (g_hVmm)  { FreeLibrary(g_hVmm);  g_hVmm  = NULL; }
    if (g_hLeech){ FreeLibrary(g_hLeech); g_hLeech = NULL; }
    if (g_hFtd)  { FreeLibrary(g_hFtd);  g_hFtd  = NULL; }

    if (g_dllDirCookie) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        typedef BOOL (WINAPI *FnRemoveDllDirectory)(DLL_DIRECTORY_COOKIE);
        auto pRemove = k32 ? (FnRemoveDllDirectory)GetProcAddress(k32, "RemoveDllDirectory") : NULL;
        if (pRemove) {
            pRemove(g_dllDirCookie);
        }
        g_dllDirCookie = NULL;
    }

    wchar_t path[MAX_PATH];
    for (int i = 0; kCleanupFiles[i]; i++) {
        BuildExtractPath(kCleanupFiles[i], path, MAX_PATH);
        DeleteFileW(path);
    }

    RemoveDirectoryW(g_dmaExtractDir);
    g_dmaExtractDir[0] = L'\0';
    g_vmmDllPath[0] = g_leechDllPath[0] = g_ftdDllPath[0] = L'\0';
    g_dllDirCookie = NULL;
    g_inited = FALSE;
}
