/* stub_stomp.c — Module stomping engine.
 *
 * Algoritmo:
 *   1. Aloca buffer "imagem" do tamanho payload.SizeOfImage.
 *   2. Copia headers + cada section pelo VirtualAddress.
 *   3. Aplica BASE relocations (delta = victim.baseVA - payload.preferredBase).
 *   4. Resolve imports (LoadLibraryEx + GetProcAddress; LL via SEARCH_SYSTEM32
 *      sempre que possível — payload importa só DLLs system).
 *   5. Marca .text/.rdata/.data/etc da vítima como RWX temporário,
 *      memcpy o buffer, restaura proteções por section.
 *   6. Resolve PayloadMain via export do buffer e devolve VA dentro da vítima.
 */
#include "stub_stomp.h"
#include "ThemidaSDK.h"
#include <string.h>

extern void WriteLogFile(const char* msg);
extern void Stub_SetLoadingText(const wchar_t* text);

/* === RELOCS ============================================================= */
static int apply_relocs(BYTE* image, const StubPE* pe, INT64 delta) {
    if (pe->relocSize == 0 || pe->relocRVA == 0) return 0;  /* sem relocs OK */
    BYTE* relocPtr = image + pe->relocRVA;
    BYTE* relocEnd = relocPtr + pe->relocSize;
    while (relocPtr < relocEnd) {
        IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)relocPtr;
        if (blk->SizeOfBlock < sizeof(*blk) || blk->SizeOfBlock > pe->relocSize) break;
        DWORD count = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
        WORD* entries = (WORD*)(relocPtr + sizeof(*blk));
        for (DWORD i = 0; i < count; i++) {
            WORD e = entries[i];
            WORD type = e >> 12;
            WORD off  = e & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* p = (ULONGLONG*)(image + blk->VirtualAddress + off);
                *p += (ULONGLONG)delta;
            } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                /* skip — padding */
            } else {
                /* tipos não usados em PE32+ moderno; tratamos como erro */
                return -3;
            }
        }
        relocPtr += blk->SizeOfBlock;
    }
    return 0;
}

/* === IMPORTS ============================================================ */
static int apply_imports(BYTE* image, const StubPE* pe) {
    if (pe->importSize == 0 || pe->importRVA == 0) return 0;
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(image + pe->importRVA);
    for (; imp->Name; imp++) {
        const char* dllName = (const char*)(image + imp->Name);
        HMODULE hMod = LoadLibraryExA(dllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!hMod) {
            /* Fallback: SEARCH_DEFAULT_DIRS para libs de plugin se for o caso */
            hMod = LoadLibraryExA(dllName, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        }
        if (!hMod) {
            char b[160]; wsprintfA(b, "stomp imports: LoadLibraryEx failed for %s", dllName);
            WriteLogFile(b);
            return -4;
        }
        ULONGLONG* iat = (ULONGLONG*)(image + imp->FirstThunk);
        ULONGLONG* lookup = (ULONGLONG*)(image +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        /* CRITICAL: quando OFT==0, lookup e iat são o MESMO array.  Devemos
         * snapshot do valor antes de sobrescrever via *iat, senão o loop
         * lê o ponteiro de função recém-escrito como próxima entrada. */
        for (; ; lookup++, iat++) {
            ULONGLONG name_or_ord = *lookup;
            if (name_or_ord == 0) break;
            FARPROC fn = NULL;
            if (name_or_ord & IMAGE_ORDINAL_FLAG64) {
                fn = GetProcAddress(hMod, (LPCSTR)(name_or_ord & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(image + name_or_ord);
                fn = GetProcAddress(hMod, ibn->Name);
            }
            if (!fn) {
                char b[160]; wsprintfA(b, "stomp imports: GetProcAddress failed in %s", dllName);
                WriteLogFile(b);
                return -4;
            }
            *iat = (ULONGLONG)fn;
        }
    }
    return 0;
}

/* === EXPORT LOOKUP ====================================================== */
/* Procura PayloadMain no export do buffer já relocado. */
static FARPROC find_payload_export(BYTE* image, const StubPE* pe) {
    if (pe->exportRVA == 0 || pe->exportSize == 0) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(image + pe->exportRVA);
    DWORD* names    = (DWORD*)(image + exp->AddressOfNames);
    DWORD* funcs    = (DWORD*)(image + exp->AddressOfFunctions);
    WORD*  ordinals = (WORD*)(image + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = (const char*)(image + names[i]);
        if (strcmp(nm, "PayloadMain") == 0) {
            DWORD funcRVA = funcs[ordinals[i]];
            return (FARPROC)(image + funcRVA);
        }
    }
    return NULL;
}

/* === STOMP ============================================================== */
int StubStomp_Apply(const StubPE* pe, StubVictim* victim, PFN_PayloadMain* outEntry) {
    VM_START
    int rc_out = -1;
    BYTE* image = NULL;
    if (!pe || !victim || !outEntry) { goto done; }
    if (pe->sizeOfImage > victim->sizeOfImage) {
        WriteLogFile("StubStomp_Apply: payload image > victim image");
        goto done;
    }

    /* 1. buffer da imagem */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Alloc]");
    image = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pe->sizeOfImage);
    if (!image) { goto done; }

    /* 2. headers + sections em layout virtual */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Copy Sections]");
    memcpy(image, pe->raw, pe->sizeOfHeaders);
    for (WORD i = 0; i < pe->nSects; i++) {
        const IMAGE_SECTION_HEADER* s = &pe->sects[i];
        if (s->SizeOfRawData == 0) continue;
        if (s->PointerToRawData + s->SizeOfRawData > pe->rawLen) {
            goto done;
        }
        memcpy(image + s->VirtualAddress,
               pe->raw + s->PointerToRawData,
               s->SizeOfRawData);
    }

    /* 3. relocs */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Relocs]");
    INT64 delta = (INT64)victim->baseVA - (INT64)pe->preferredBase;
    int rc = apply_relocs(image, pe, delta);
    if (rc != 0) { rc_out = rc; goto done; }

    /* 4. imports */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Imports]");
    rc = apply_imports(image, pe);
    if (rc != 0) { rc_out = rc; goto done; }

    /* 5. localizar PayloadMain no buffer relocado (RVA está consistente
     *    com o futuro VA dentro da vítima após o memcpy) */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Find Export]");
    FARPROC entryInBuf = find_payload_export(image, pe);
    if (!entryInBuf) {
        WriteLogFile("StubStomp_Apply: no PayloadMain export");
        rc_out = -5;
        goto done;
    }

    /* 6. Toda imagem RWX para o memcpy.  Depois aplicamos proteção
     *    POR-SECTION conforme Characteristics — svc.dll TEM .data que
     *    precisa ser writable em runtime (KeyAuth state, patch globals). */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: VProtect]");
    DWORD oldProt = 0;
    if (!VirtualProtect(victim->baseVA, victim->sizeOfImage,
                        PAGE_EXECUTE_READWRITE, &oldProt)) {
        rc_out = -2;
        goto done;
    }
    Stub_SetLoadingText(L"Loading cheat... [Stomp: MemCpy]");
    memcpy(victim->baseVA, image, pe->sizeOfImage);

    /* Headers: read-only — skip since VirtualProtect after RWX on loaded DLL
     * can hang under certain OS lock conditions.  Victim is reverted anyway. */
    /* REMOVED: VirtualProtect(victim->baseVA, pe->sizeOfHeaders, PAGE_READONLY, &r); */

    /* NOTE: Per-section VirtualProtect loop removed — causes deadlock hang
     * on .pdata / .fptable section updates.  Victim fully reverted post-run. */

    /* O PayloadMain agora está no offset (entryInBuf - image) dentro da vítima */
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Entry Resolve]");
    SIZE_T entryOff = (BYTE*)entryInBuf - image;
    *outEntry = (PFN_PayloadMain)(victim->baseVA + entryOff);

    rc_out = 0;

done:
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Cleanup]");
    if (image) {
        /* Use memset instead of RtlSecureZeroMemory — the latter zeroes byte-by-byte
         * which is extremely slow for 1.1MB inside a Themida VM region. */
        memset(image, 0, pe->sizeOfImage);
        HeapFree(GetProcessHeap(), 0, image);
    }
    Stub_SetLoadingText(L"Loading cheat... [Stomp: Done]");
    VM_END
    return rc_out;
}

int StubStomp_Revert(StubVictim* v) {
    if (!v || !v->snapshot || !v->baseVA) return -1;
    DWORD oldProt = 0;
    if (!VirtualProtect(v->baseVA, v->sizeOfImage,
                        PAGE_EXECUTE_READWRITE, &oldProt)) return -2;
    memcpy(v->baseVA, v->snapshot, v->snapshotLen);
    DWORD restore = 0;
    VirtualProtect(v->baseVA, v->sizeOfImage, PAGE_EXECUTE_READ, &restore);
    return 0;
}
