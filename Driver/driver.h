#pragma once
#include <ntddk.h>
#include <bcrypt.h>
#include <wdm.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include "shared.h"
#include "shadow_mem.h"

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        } s;
    } u;
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    } u1;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONG64 ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG64 SizeOfStackReserve;
    ULONG64 SizeOfStackCommit;
    ULONG64 SizeOfHeapReserve;
    ULONG64 SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#endif

/* No ZwCreatePort needed — SHM IPC uses ZwCreateSection/ZwCreateEvent which ARE exported */
NTSYSAPI NTSTATUS NTAPI ZwCreateSection(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
NTSYSAPI NTSTATUS NTAPI ZwMapViewOfSection(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,SECTION_INHERIT,ULONG,ULONG);
NTSYSAPI NTSTATUS NTAPI ZwUnmapViewOfSection(HANDLE,PVOID);
NTSYSAPI NTSTATUS NTAPI ZwCreateEvent(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,EVENT_TYPE,BOOLEAN);
#define ViewUnmap   1
#define SEC_COMMIT  0x08000000

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE,PEPROCESS*);
typedef struct _RTL_PROCESS_MODULE_INFORMATION { HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256]; } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
// PsLoadedModuleList removed to ensure symbol resolution success on Win10 22H2
typedef struct _HARDWARE_PTE{ULONG64 Valid:1;ULONG64 Write:1;ULONG64 User:1;ULONG64 WriteThrough:1;ULONG64 CacheDisable:1;ULONG64 Accessed:1;ULONG64 Dirty:1;ULONG64 LargePage:1;ULONG64 Global:1;ULONG64 CopyOnWrite:1;ULONG64 Prototype:1;ULONG64 reserved0:1;ULONG64 PageFrameNumber:36;ULONG64 reserved1:4;ULONG64 SoftwareReserved:11;ULONG64 NoExecute:1;}HARDWARE_PTE,*PHARDWARE_PTE;
typedef struct _SPFN_CTX{
    KSPIN_LOCK      lock;
    HANDLE          reg_key;
    LONG            shutdown;
    HANDLE          worker_thread;
    /* Shared Memory IPC */
    HANDLE          section_handle;
    PVOID           shm_kva;
    SVC_SHM*     shm;
    /* Sync events: handles for ZwCreateEvent (passed to loader via ZwDuplicateObject)
       and PKEVENT object pointers for KeWait/KeSet in driver worker thread */
    HANDLE          h_event_u2k;      /* handle created by ZwCreateEvent             */
    HANDLE          h_event_k2u;      /* handle created by ZwCreateEvent             */
    PKEVENT         event_u2k_obj;    /* PKEVENT from ObReferenceObjectByHandle(u2k) */
    PKEVENT         event_k2u_obj;    /* PKEVENT from ObReferenceObjectByHandle(k2u) */

    /* Crypto */
    BCRYPT_ALG_HANDLE hAlgHash;
    BCRYPT_ALG_HANDLE hAlgAes;
    UCHAR           master_key[KEY_SIZE];
    UCHAR           session_key[KEY_SIZE];
    BCRYPT_KEY_HANDLE hSessionKey;    /* derived once per handshake   */
    /* Process/memory scan state */
    EVASION_CONTEXT evasion_ctx;
    PVOID           MmPfnDatabase;
    PVOID           DirectMapBase;
    ULONG           PfnEntrySize;
    ULONG           PageLocationOffset;
    ULONG           DirectoryTableBaseOffset;
    ULONG           PebOffset;
    ULONG           UniqueProcessIdOffset;
    ULONG           ActiveProcessLinksOffset;
    PPHYSICAL_MEMORY_RANGE PhysMemRanges;
    ULONG           PhysRangeCount;
    /* Shadow memory — MmCopyVirtualMemory hook for BE scan spoofing */
    SHADOW_CTX      shadowCtx;
}SPFN_CTX;
#ifdef __cplusplus
extern "C" {
#endif
NTSTATUS DriverEntry(PDRIVER_OBJECT,PUNICODE_STRING);
#ifdef __cplusplus
}
#endif
VOID DriverUnload(PDRIVER_OBJECT);
NTSTATUS SPFN_Initialize(SPFN_CTX*,PUNICODE_STRING);
NTSTATUS SPFN_StartServer(SPFN_CTX*);
NTSTATUS SPFN_Worker(PVOID);
NTSTATUS SPI_Encrypt(SPFN_CTX*,PUCHAR,ULONG,PUCHAR,PULONG);
NTSTATUS SPI_Decrypt(SPFN_CTX*,PUCHAR,ULONG,PUCHAR,PULONG);
NTSTATUS SetPageLocation(ULONG_PTR,ULONG);
NTSTATUS CamouflagePage(ULONG_PTR,ULONG,PUCHAR,ULONG);
NTSTATUS HideDriver(PDRIVER_OBJECT);
VOID SPFN_Cleanup(SPFN_CTX*);
PVOID FindMmPfnDatabase();
ULONG DetectPfnEntrySize();
ULONG DetectPageLocationOffset();
NTSTATUS InitializePhysRanges(SPFN_CTX*);
PVOID MapPhysicalAddress(SPFN_CTX*,ULONG64);
BOOLEAN IsPhysAddressSafe(SPFN_CTX*,ULONG64);
NTSTATUS WalkPageTable(SPFN_CTX*,ULONG64,ULONG64,ULONG64*,BOOLEAN*);
NTSTATUS GhostReadWrite(SPFN_CTX*,ULONG64,ULONG64,PVOID,SIZE_T,BOOLEAN);
NTSTATUS GetProcessCr3(SPFN_CTX*,HANDLE,ULONG64*);
NTSTATUS ReadProcessMemoryByCr3(SPFN_CTX*,ULONG64,ULONG64,PVOID,SIZE_T);
NTSTATUS WriteProcessMemoryByCr3(SPFN_CTX*,ULONG64,ULONG64,PVOID,SIZE_T);
NTSTATUS GetModuleBaseByPid(SPFN_CTX*,HANDLE,PCWSTR,ULONG64*);
NTSTATUS HideProcess(SPFN_CTX*,HANDLE);
NTSTATUS DetectProcessOffsets(SPFN_CTX*);
