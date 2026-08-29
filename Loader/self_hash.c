/* self_hash.c — implementação do self-integrity check (P6.1).
 * Hash composto: SHA256(.text || .rdata) — cobre tanto código quanto
 * constantes (tabelas de AOB, chaves XOR) sem auto-referência
 * (g_selfHashBlock está em .data, excluído do hash). */
#include "self_hash.h"
#include "keyauth.h"
#include "debug.h"
#include <bcrypt.h>
#include "syscalls.h"  /* SeraphSleep */
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* Placeholder com magic + 32 bytes a serem sobrescritos pelo embed_hash.py.
 * Volátil para impedir o linker de constant-fold em otimização agressiva.
 * Globalmente inicializado → automaticamente vai para `.data`.
 *
 * SECURITY: magic é composto de bytes não-ASCII (0xFE 0xED 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE)
 * para não aparecer em scanners de strings (strings(1) filtra sequências < 4 ASCII imprimíveis).
 * embed_hash.py busca exatamente esses 8 bytes + 32 bytes 0xAA. */
volatile BYTE g_selfHashBlock[8 + 32] = {
    /* magic — 8 bytes não-ASCII, invisível a strings(1) */
    0xFE,0xED,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    /* placeholder — substituído pelo hash SHA256 em post-link */
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
};

/* Computa SHA256 de um buffer via BCrypt. */
static BOOL sha256_buf(const BYTE* data, ULONG len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL ok = FALSE;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, len, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
        goto done;
    ok = TRUE;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

BOOL SelfHash_Verify(void) {
    /* Se ainda 0xAA → build sem post-link.  Em DEV permitimos; em RELEASE
     * post-link script DEVE rodar antes do release. */
    BOOL placeholderUntouched = TRUE;
    for (int i = 0; i < 32; i++) {
        if (g_selfHashBlock[8 + i] != 0xAA) { placeholderUntouched = FALSE; break; }
    }
    if (placeholderUntouched) {
#ifndef NDEBUG
        WriteLogFile("SelfHash_Verify: placeholder untouched (DEV build) — OK");
        return TRUE;
#else
        WriteLogFile("SelfHash_Verify: placeholder untouched in RELEASE — aborting");
        KeyAuth_BanCurrentKey();
        ExitProcess(0xDEADA0);
        return FALSE;
#endif
    }

    /* Localizar .text e .rdata via PE headers do próprio módulo. */
    HMODULE hSelf = GetModuleHandleW(NULL);
    BYTE* base = (BYTE*)hSelf;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sects = (IMAGE_SECTION_HEADER*)
        ((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    BYTE* textVA   = NULL; DWORD textSize   = 0;
    BYTE* rdataVA  = NULL; DWORD rdataSize  = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sects[i].Name, ".text", 5) == 0) {
            textVA   = base + sects[i].VirtualAddress;
            textSize = sects[i].Misc.VirtualSize ? sects[i].Misc.VirtualSize
                                                 : sects[i].SizeOfRawData;
        } else if (memcmp(sects[i].Name, ".rdata", 6) == 0) {
            rdataVA  = base + sects[i].VirtualAddress;
            rdataSize= sects[i].Misc.VirtualSize ? sects[i].Misc.VirtualSize
                                                 : sects[i].SizeOfRawData;
        }
    }

    if (!textVA || textSize == 0) {
        WriteLogFile("SelfHash_Verify: no .text — cannot verify");
        return FALSE;
    }

    /* Compute SHA256(.text || .rdata) in a single BCrypt hash pass. */
    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE computed[32] = {0};
    BOOL hashOk = FALSE;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto _sh_done;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
        goto _sh_done;
    if (!NT_SUCCESS(BCryptHashData(hHash, textVA, textSize, 0)))
        goto _sh_done;
    /* Include .rdata if found */
    if (rdataVA && rdataSize > 0) {
        if (!NT_SUCCESS(BCryptHashData(hHash, rdataVA, rdataSize, 0)))
            goto _sh_done;
    }
    if (!NT_SUCCESS(BCryptFinishHash(hHash, computed, 32, 0)))
        goto _sh_done;
    hashOk = TRUE;

_sh_done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!hashOk) {
        WriteLogFile("SelfHash_Verify: BCrypt SHA256 failed");
        return FALSE;
    }

    /* Compare constant-time. */
    BYTE diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ g_selfHashBlock[8 + i];
    if (diff == 0) {
        WriteLogFile("SelfHash_Verify: OK");
        return TRUE;
    }

    WriteLogFile("SelfHash_Verify: MISMATCH — tampered binary");
#ifdef NDEBUG
    KeyAuth_BanCurrentKey();
    SeraphSleep(300);
    ExitProcess(0xDEADA1);
#endif
    return FALSE;
}
