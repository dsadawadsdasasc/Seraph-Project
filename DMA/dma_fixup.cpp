/*

 * dma_fixup.cpp — MemProcFS init helpers ported from Vanish DMALibrary.

 */



#include "dma_fixup.h"

#include "dma_dll_loader.h"



#include "../../DMA-Lib-main/Teeko-DMA-Lib-main/Teeko-DMA-Lib/Teeko-DMA-Lib/Teeko-DMA/deps/vmmdll.h"

#include "../../DMA-Lib-main/Teeko-DMA-Lib-main/Teeko-DMA-Lib/Teeko-DMA-Lib/Teeko-DMA/deps/leechcore.h"



#include <cstdio>

#include <cstring>

#include <fstream>

#include <sstream>

#include <string>



static unsigned char s_fpgaAbort[4] = { 0x10, 0x00, 0x10, 0x00 };



static BOOL DmaGetMmapPathW(wchar_t *out, DWORD cch) {

    if (!out || cch < 16) return FALSE;

    DWORD n = GetTempPathW(cch, out);

    if (!n || n >= cch - 12) return FALSE;

    if (out[n - 1] != L'\\') wcscat_s(out, cch, L"\\");

    wcscat_s(out, cch, L"mmap.txt");

    return TRUE;

}



extern "C" BOOL DmaDumpMemoryMap(void) {

    DmaLoader_EnsureSearchPath();

    LPCSTR args[] = { "-device", "fpga", "-waitinitialize", "-norefresh" };

    VMM_HANDLE h = VMMDLL_Initialize(4, args);

    if (!h) return FALSE;



    PVMMDLL_MAP_PHYSMEM pMap = nullptr;

    BOOL ok = FALSE;

    if (!VMMDLL_Map_GetPhysMem(h, &pMap) || !pMap ||

        pMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION || pMap->cMap == 0) {

        goto done;

    }



    {

        std::stringstream sb;

        for (DWORD i = 0; i < pMap->cMap; i++)

            sb << std::hex << pMap->pMap[i].pa << " "

               << (pMap->pMap[i].pa + pMap->pMap[i].cb - 1) << std::endl;



        wchar_t path[MAX_PATH];

        if (!DmaGetMmapPathW(path, MAX_PATH)) goto done;



        char pathA[MAX_PATH];

        WideCharToMultiByte(CP_UTF8, 0, path, -1, pathA, MAX_PATH, nullptr, nullptr);

        std::ofstream f(pathA, std::ios::trunc);

        if (!f) goto done;

        f << sb.str();

        f.close();

        ok = TRUE;

    }



done:

    if (pMap) VMMDLL_MemFree(pMap);

    if (h) VMMDLL_Close(h);

    if (ok) Sleep(1500);

    return ok;

}



extern "C" BOOL DmaEnsureMemoryMap(void) {

    wchar_t path[MAX_PATH];

    if (!DmaGetMmapPathW(path, MAX_PATH)) return FALSE;

    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) return TRUE;

    return DmaDumpMemoryMap();

}



extern "C" BOOL DmaSetFPGA(void *vmmHandle) {

    VMM_HANDLE h = (VMM_HANDLE)vmmHandle;

    if (!h) return FALSE;



    ULONG64 id = 0, maj = 0, min = 0;

    VMMDLL_ConfigGet(h, LC_OPT_FPGA_FPGA_ID, &id);

    VMMDLL_ConfigGet(h, LC_OPT_FPGA_VERSION_MAJOR, &maj);

    VMMDLL_ConfigGet(h, LC_OPT_FPGA_VERSION_MINOR, &min);



    if ((maj >= 4) && ((maj >= 5) || (min >= 7))) {

        LC_CONFIG cfg = {};

        cfg.dwVersion = LC_CONFIG_VERSION;

        strcpy_s(cfg.szDevice, "existing");

        HANDLE lc = LcCreate(&cfg);

        if (!lc) return FALSE;

        LcCommand(lc, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, 4,

            reinterpret_cast<PBYTE>(s_fpgaAbort), nullptr, nullptr);

        LcClose(lc);

    }

    return TRUE;

}

