/* stub_pe_parser.c — implementação do parser PE32+ para module stomping. */
#include "stub_pe_parser.h"
#include "ThemidaSDK.h"
#include <string.h>

extern void WriteLogFile(const char* msg);

int StubPE_Parse(StubPE* out, const BYTE* raw, SIZE_T rawLen) {
    MUTATE_START
    int rc = 0;
    if (!out || !raw || rawLen < sizeof(IMAGE_DOS_HEADER)) { rc = -1; goto done; }
    memset(out, 0, sizeof(*out));
    out->raw    = raw;
    out->rawLen = rawLen;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        WriteLogFile("StubPE_Parse: bad DOS magic");
        rc = -2; goto done;
    }
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > rawLen) { rc = -2; goto done; }

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        WriteLogFile("StubPE_Parse: bad NT signature");
        rc = -3; goto done;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        WriteLogFile("StubPE_Parse: not AMD64");
        rc = -3; goto done;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        WriteLogFile("StubPE_Parse: not PE32+");
        rc = -3; goto done;
    }

    out->dos = dos;
    out->nt  = nt;
    out->opt = &nt->OptionalHeader;
    out->nSects = nt->FileHeader.NumberOfSections;

    out->sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    out->sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    out->preferredBase = nt->OptionalHeader.ImageBase;
    out->entryRVA      = nt->OptionalHeader.AddressOfEntryPoint;

    if (out->nSects == 0 || out->nSects > 96) { rc = -4; goto done; }
    if (out->sizeOfImage < out->sizeOfHeaders) { rc = -4; goto done; }

    /* Data directories que nos interessam */
    IMAGE_DATA_DIRECTORY* dd = nt->OptionalHeader.DataDirectory;
    out->relocRVA  = dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    out->relocSize = dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    out->importRVA = dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    out->importSize= dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    out->exportRVA = dd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    out->exportSize= dd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    out->tlsRVA    = dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    out->tlsSize   = dd[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    out->exceptionRVA  = dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    out->exceptionSize = dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    /* Section table — 1 byte após o Optional Header */
    out->sects = (IMAGE_SECTION_HEADER*)
        ((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    /* Localiza .text */
    for (WORD i = 0; i < out->nSects; i++) {
        IMAGE_SECTION_HEADER* s = &out->sects[i];
        if (memcmp(s->Name, ".text", 5) == 0) {
            out->textRVA          = s->VirtualAddress;
            out->textVirtualSize  = s->Misc.VirtualSize;
            out->textRawOffset    = s->PointerToRawData;
            out->textRawSize      = s->SizeOfRawData;
            break;
        }
    }
    if (!out->textRVA) {
        WriteLogFile("StubPE_Parse: no .text section");
        rc = -5; goto done;
    }
done:
    MUTATE_END
    return rc;
}

const BYTE* StubPE_RVAToRaw(const StubPE* pe, DWORD rva) {
    MUTATE_START
    const BYTE* res = NULL;
    if (!pe || !pe->raw) { goto done; }
    /* Se cair em headers (antes da primeira section) */
    if (rva < pe->sizeOfHeaders) {
        if (rva >= pe->rawLen) { goto done; }
        res = pe->raw + rva;
        goto done;
    }
    for (WORD i = 0; i < pe->nSects; i++) {
        const IMAGE_SECTION_HEADER* s = &pe->sects[i];
        DWORD vaStart = s->VirtualAddress;
        DWORD vaEnd   = vaStart + (s->Misc.VirtualSize ? s->Misc.VirtualSize
                                                       : s->SizeOfRawData);
        if (rva >= vaStart && rva < vaEnd) {
            DWORD delta = rva - vaStart;
            if (delta >= s->SizeOfRawData) { goto done; }  /* RVA além do raw — bss */
            SIZE_T off = (SIZE_T)s->PointerToRawData + delta;
            if (off >= pe->rawLen) { goto done; }
            res = pe->raw + off;
            goto done;
        }
    }

done:
    MUTATE_END
    return res;
}

const IMAGE_SECTION_HEADER* StubPE_FindSection(const StubPE* pe, const char* name8) {
    MUTATE_START
    const IMAGE_SECTION_HEADER* res = NULL;
    if (!pe || !name8) { goto done; }
    char buf[8] = {0};
    for (int i = 0; i < 8 && name8[i]; i++) buf[i] = name8[i];
    for (WORD i = 0; i < pe->nSects; i++) {
        if (memcmp(pe->sects[i].Name, buf, 8) == 0) {
            res = &pe->sects[i];
            goto done;
        }
    }

done:
    MUTATE_END
    return res;
}
