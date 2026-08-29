#pragma once
#include <ntddk.h>

/* Dynamic BCrypt resolver — takes cng.sys base address (found by caller via ZwQuerySystemInformation)
   and walks its PE export table to resolve BCrypt functions without a static cng.sys import. */

typedef NTSTATUS (NTAPI *PFN_BCryptOpenAlgorithmProvider)(PVOID*,PCWSTR,PCWSTR,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptCloseAlgorithmProvider)(PVOID,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptSetProperty)(PVOID,PCWSTR,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptGenRandom)(PVOID,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptCreateHash)(PVOID,PVOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptHashData)(PVOID,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptFinishHash)(PVOID,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptDestroyHash)(PVOID);
typedef NTSTATUS (NTAPI *PFN_BCryptGenerateSymmetricKey)(PVOID,PVOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptEncrypt)(PVOID,PUCHAR,ULONG,PVOID,PUCHAR,ULONG,PUCHAR,ULONG,PULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptDecrypt)(PVOID,PUCHAR,ULONG,PVOID,PUCHAR,ULONG,PUCHAR,ULONG,PULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_BCryptDestroyKey)(PVOID);

typedef struct _BCRYPT_DYN {
    PFN_BCryptOpenAlgorithmProvider  OpenAlgorithmProvider;
    PFN_BCryptCloseAlgorithmProvider CloseAlgorithmProvider;
    PFN_BCryptSetProperty            SetProperty;
    PFN_BCryptGenRandom              GenRandom;
    PFN_BCryptCreateHash             CreateHash;
    PFN_BCryptHashData               HashData;
    PFN_BCryptFinishHash             FinishHash;
    PFN_BCryptDestroyHash            DestroyHash;
    PFN_BCryptGenerateSymmetricKey   GenerateSymmetricKey;
    PFN_BCryptEncrypt                Encrypt;
    PFN_BCryptDecrypt                Decrypt;
    PFN_BCryptDestroyKey             DestroyKey;
} BCRYPT_DYN;

extern BCRYPT_DYN g_BC;

/* Minimal PE structures for export table walking */
typedef struct _BC_EXPORT_DIR {
    ULONG Characteristics; ULONG TimeDateStamp;
    USHORT MajorVersion;   USHORT MinorVersion;
    ULONG Name;            ULONG Base;
    ULONG NumberOfFunctions; ULONG NumberOfNames;
    ULONG AddressOfFunctions; ULONG AddressOfNames; ULONG AddressOfNameOrdinals;
} BC_EXPORT_DIR;

/* Walk PE export table to find a named function */
static __inline PVOID BC_GetExport(PVOID base, const char* name) {
    if (!base) return NULL;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != 0x5A4D) return NULL;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dos->e_lfanew);
        if (nt->Signature != 0x00004550) return NULL;
        ULONG expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
        if (!expRva) return NULL;
        BC_EXPORT_DIR* exp = (BC_EXPORT_DIR*)((PUCHAR)base + expRva);
        PULONG  names = (PULONG) ((PUCHAR)base + exp->AddressOfNames);
        PULONG  funcs = (PULONG) ((PUCHAR)base + exp->AddressOfFunctions);
        PUSHORT ords  = (PUSHORT)((PUCHAR)base + exp->AddressOfNameOrdinals);
        for (ULONG i = 0; i < exp->NumberOfNames; i++) {
            const char* en = (const char*)((PUCHAR)base + names[i]);
            const char* a = name, *b = en;
            while (*a && *a == *b) { a++; b++; }
            if (!*a && !*b) return (PVOID)((PUCHAR)base + funcs[ords[i]]);
        }
    } __except(1) {}
    return NULL;
}

/* Initialize BCrypt function pointers from a known cng.sys base address */
static __inline NTSTATUS BC_InitWithBase(PVOID cngBase) {
    if (!cngBase) return STATUS_NOT_FOUND;
    struct { const char* n; PVOID* f; } t[] = {
        {"BCryptOpenAlgorithmProvider",  (PVOID*)&g_BC.OpenAlgorithmProvider},
        {"BCryptCloseAlgorithmProvider", (PVOID*)&g_BC.CloseAlgorithmProvider},
        {"BCryptSetProperty",            (PVOID*)&g_BC.SetProperty},
        {"BCryptGenRandom",              (PVOID*)&g_BC.GenRandom},
        {"BCryptCreateHash",             (PVOID*)&g_BC.CreateHash},
        {"BCryptHashData",               (PVOID*)&g_BC.HashData},
        {"BCryptFinishHash",             (PVOID*)&g_BC.FinishHash},
        {"BCryptDestroyHash",            (PVOID*)&g_BC.DestroyHash},
        {"BCryptGenerateSymmetricKey",   (PVOID*)&g_BC.GenerateSymmetricKey},
        {"BCryptEncrypt",                (PVOID*)&g_BC.Encrypt},
        {"BCryptDecrypt",                (PVOID*)&g_BC.Decrypt},
        {"BCryptDestroyKey",             (PVOID*)&g_BC.DestroyKey},
    };
    for (int i = 0; i < 12; i++) {
        *t[i].f = BC_GetExport(cngBase, t[i].n);
        if (!*t[i].f) return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

/* Macros redirect all BCrypt calls to dynamic pointers */
#define BCryptOpenAlgorithmProvider  g_BC.OpenAlgorithmProvider
#define BCryptCloseAlgorithmProvider g_BC.CloseAlgorithmProvider
#define BCryptSetProperty            g_BC.SetProperty
#define BCryptGenRandom              g_BC.GenRandom
#define BCryptCreateHash             g_BC.CreateHash
#define BCryptHashData               g_BC.HashData
#define BCryptFinishHash             g_BC.FinishHash
#define BCryptDestroyHash            g_BC.DestroyHash
#define BCryptGenerateSymmetricKey   g_BC.GenerateSymmetricKey
#define BCryptEncrypt                g_BC.Encrypt
#define BCryptDecrypt                g_BC.Decrypt
#define BCryptDestroyKey             g_BC.DestroyKey
