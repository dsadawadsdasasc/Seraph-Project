#ifndef SVCNAME
#define SVCNAME XOR_W(L"NdProxy")
#endif
#include "driver.h"
#include "evasion_kernel.h"
#include "XorStr.h"
#include "bcrypt_dynamic.h"
#include "debug_kernel.h"  /* D-DRV-1: kernel-safe debug macros (was ../Loader/debug.h) */

BCRYPT_DYN g_BC={0};
static SPFN_CTX* g_ShadowPfnCtx=NULL;
typedef struct _PiDDBCacheEntry{LIST_ENTRY List;UNICODE_STRING DriverName;ULONG TimeDateStamp;NTSTATUS LoadStatus;char _0[16];}PiDDBCacheEntry,*PPiDDBCacheEntry;
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);

/* OS version detection */
static ULONG g_WindowsBuildNumber = 0;

static VOID DetectWindowsVersion(void) {
    DEBUG_ENTER_FUNCTION();
    if (g_WindowsBuildNumber != 0) {
        DEBUG_EXIT_FUNCTION();
        return;
    }
    
    /* Try to get build number from shared kernel data (KUSER_SHARED_DATA) */
    __try {
        /* KUSER_SHARED_DATA at 0xFFFFF78000000000 contains NtBuildNumber at offset 0x260 */
        ULONG* pBuild = (ULONG*)0xFFFFF78000000260ULL;
        if (MmIsAddressValid(pBuild)) {
            g_WindowsBuildNumber = *pBuild;
            DEBUG_PRINT("Detected Windows build number from KUSER_SHARED_DATA: %lu", g_WindowsBuildNumber);
            DEBUG_EXIT_FUNCTION();
            return;
        }
    } __except(1) {
        DEBUG_ERROR("Exception reading KUSER_SHARED_DATA");
    }
    
    /* Fallback: query system information */
    typedef struct _SYSTEM_INFORMATION_CLASS_BUILD {
        ULONG BuildNumber;
    } SYSTEM_INFORMATION_CLASS_BUILD;
    
    SYSTEM_INFORMATION_CLASS_BUILD info = {0};
    ULONG retLen = 0;
    if (NT_SUCCESS(ZwQuerySystemInformation(0x5B /* SystemKernelDebuggerInformationEx? */,
                                            &info, sizeof(info), &retLen))) {
        g_WindowsBuildNumber = info.BuildNumber;
        DEBUG_PRINT("Detected Windows build number from ZwQuerySystemInformation: %lu", g_WindowsBuildNumber);
    } else {
        /* Default to Windows 10 22H2 (19045) */
        g_WindowsBuildNumber = 19045;
        DEBUG_PRINT("Failed to detect Windows build, defaulting to: %lu", g_WindowsBuildNumber);
    }
    DEBUG_EXIT_FUNCTION();
}

static ULONG GetWindowsBuildNumber(void) {
    if (g_WindowsBuildNumber == 0) {
        DetectWindowsVersion();
    }
    return g_WindowsBuildNumber;
}
/* D-DRV-3: GetModuleBase with retry on buffer too small.
 * ZwQSI(11) may return a larger needed size if modules are loaded between calls. */
static PVOID GetModuleBase(const char* modname){
PVOID p=NULL;ULONG s=0;
ZwQuerySystemInformation(11,NULL,0,&s);
if(!s)return NULL;
s+=0x4000;  /* headroom for modules loaded between calls */
PRTL_PROCESS_MODULES m=(PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx,s,'nlmF'); /* fltmgr.sys tag */
if(!m)return NULL;
NTSTATUS st=ZwQuerySystemInformation(11,m,s,&s);
if(st==0xC0000023L /*STATUS_INFO_LENGTH_MISMATCH*/){
    /* Retry with updated size — D-DRV-3 */
    ExFreePool(m);
    s+=0x1000;  /* extra page for safety */
    m=(PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx,s,'nlmF'); /* fltmgr.sys tag */
    if(!m)return NULL;
    st=ZwQuerySystemInformation(11,m,s,&s);
}
if(NT_SUCCESS(st)){
    for(ULONG i=0;i<m->NumberOfModules;i++){
        const char* fn=(const char*)m->Modules[i].FullPathName+m->Modules[i].OffsetToFileName;
        const char* a=modname;const char* b=fn;
        while(*a&&*b){
            char ca=*a,cb=*b;
            if(ca>='A'&&ca<='Z')ca+=32;if(cb>='A'&&cb<='Z')cb+=32;
            if(ca!=cb)break;a++;b++;
        }
        if(!*a&&!*b){p=m->Modules[i].ImageBase;break;}
    }
}
ExFreePool(m);return p;}
static ULONG g_KernelImageSize=0;
PVOID GetKernelBase(){
PVOID p=NULL;ULONG s=0;ZwQuerySystemInformation(11,NULL,0,&s);
if(s){s+=0x4000;
PRTL_PROCESS_MODULES m=(PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx,s,'bSdN'); /* ndis.sys tag */
if(m){if(NT_SUCCESS(ZwQuerySystemInformation(11,m,s,&s))){p=m->Modules[0].ImageBase;g_KernelImageSize=m->Modules[0].ImageSize;}ExFreePool(m);}}
return p;}
/* FindPattern: scan is bounded by actual image size (g_KernelImageSize) to never go past valid pages.
   __try/__except guards against page faults on freed .INIT section pages (freed after boot). */
PVOID FindPattern(PVOID b,ULONG s,const char* p,const char* m){
ULONG ml=(ULONG)strlen(m);if(!b||!ml||s<ml)return NULL;ULONG limit=s-ml;
__try{
for(ULONG i=0;i<=limit;i++){BOOLEAN f=TRUE;for(ULONG j=0;j<ml;j++){if(m[j]=='x'&&((UCHAR*)b)[i+j]!=((UCHAR*)p)[j]){f=FALSE;break;}}if(f)return(PUCHAR)b+i;}
}__except(1){}
return NULL;}

PVOID ResolveRel(PVOID p,ULONG o,ULONG l){return(PVOID)((char*)p+l+*(LONG*)((char*)p+o));}
/* HideThread: Win32StartAddress spoof.
 * Instead of unlinking ThreadListEntry (build-specific offset, race-prone),
 * we spoof ETHREAD.Win32StartAddress to point at a legitimate ntoskrnl function
 * (ExpWorkerThread). Anti-Cheats that call NtQueryInformationThread(
 * ThreadQuerySetWin32StartAddress) will see a system thread address, not ours.
 *
 * Offset detection strategy:
 *   1. Primary: scan ETHREAD for a value matching our known start address.
 *      We store SPFN_Worker in g_WorkerStartAddr before thread creation.
 *   2. Fallback: use per-build lookup table based on g_WindowsBuildNumber.
 *      Win10 22H2 (19045): 0x578  Win11 22H2 (22621): 0x578  Win11 23H2 (22631): 0x578
 */

static PVOID g_WorkerStartAddr = NULL; /* set in SPFN_StartServer before thread creation */

/* Returns the offset of ETHREAD.Win32StartAddress.
 * BUG FIX: We must scan for ETHREAD.StartAddress (the raw kernel start address,
 * always set by the kernel before the thread is scheduled) — NOT Win32StartAddress
 * (which is only written once the thread actually executes its first instruction).
 * Since HideKernelThread is called immediately after PsCreateSystemThread, there is
 * a race window where Win32StartAddress is still NULL. StartAddress is always valid.
 * On all Win10/Win11 x64 builds tested: Win32StartAddress = StartAddress + 8. */
static ULONG FindWin32StartAddressOffset(PETHREAD thread){
    if(!thread || !g_WorkerStartAddr) goto fallback;
    {
        ULONG_PTR base=(ULONG_PTR)thread;
        /* Scan for ETHREAD.StartAddress which kernel fills before scheduling */
        for(ULONG i=0x400;i<0x700;i+=8){
            __try{
                PVOID* slot=(PVOID*)(base+i);
                /* Read the value at this ETHREAD offset and check if it is
                 * a valid kernel VA matching our start address. The slot pointer
                 * itself is always a kernel VA (it's inside an ETHREAD in NonPagedPool)
                 * so checking slot is pointless — we must check *slot instead. */
                PVOID val = *slot;
                if(!val) continue; /* skip NULL entries */
                if((ULONG_PTR)val < 0xFFFF800000000000ULL) continue; /* not a kernel VA */
                if(val == g_WorkerStartAddr){
                    /* Found StartAddress at offset i.
                     * Win32StartAddress is StartAddress+8 on all known builds. */
                    return i + 8;
                }
            }__except(1){continue;}
        }
    }
fallback:;
    /* Build-number fallback table (verified via WinDbg dt nt!_ETHREAD) */
    ULONG build=GetWindowsBuildNumber();
    if(build>=22000) return 0x580; /* Win11 21H2 through 24H2 */
    if(build>=19041) return 0x580; /* Win10 20H1 through 22H2  */
    return 0x580;                  /* Conservative safe default  */
}

VOID HideThread(PETHREAD t){
    if(!t)return;
    /* Spoof target: ExpWorkerThread is the canonical start address for all
     * legitimate system worker threads — indistinguishable from our thread. */
    UNICODE_STRING fnName;RtlInitUnicodeString(&fnName,L"ExpWorkerThread");
    PVOID spoofTarget=MmGetSystemRoutineAddress(&fnName);
    if(!spoofTarget){
        /* Fallback: use KeWaitForSingleObject which is always exported */
        RtlInitUnicodeString(&fnName,L"KeWaitForSingleObject");
        spoofTarget=MmGetSystemRoutineAddress(&fnName);
    }
    if(!spoofTarget)return;

    ULONG offset=FindWin32StartAddressOffset(t);
    if(!offset)return;

    __try{
        PVOID* pAddr=(PVOID*)((PUCHAR)t+offset);
        /* ETHREAD is always NonPagedPool — MmIsAddressValid is redundant and can
         * mislead (it may return FALSE for valid NonPagedPool during page table
         * rebuild). Use a canonical kernel VA range check instead. */
        if((ULONG_PTR)pAddr >= 0xFFFF800000000000ULL){
            InterlockedExchangePointer(pAddr,spoofTarget);
        }
    }__except(1){}
}
VOID HideKernelThread(HANDLE h){
    PETHREAD t;if(NT_SUCCESS(ObReferenceObjectByHandle(h,THREAD_ALL_ACCESS,*PsThreadType,KernelMode,(PVOID*)&t,NULL))){HideThread(t);ObDereferenceObject(t);}
}
/* HideProcess: DKOM via UniqueProcessId spoof.
 * Instead of unlinking PsActiveProcessLinks (which requires PspActiveProcessMutex
 * and causes race-BSOD on multi-core), we zero the UniqueProcessId field in the
 * EPROCESS. NtQuerySystemInformation(SystemProcessInformation) skips entries with
 * PID == 0, making the process invisible to all usermode enumerators.
 * The EPROCESS stays linked — no lock needed, no race condition possible. */
NTSTATUS HideProcess(SPFN_CTX* ctx, HANDLE pid){
    if(!ctx||!pid)return STATUS_INVALID_PARAMETER;
    /* BUG FIX: UniqueProcessIdOffset may be 0 if DetectProcessOffsets failed and
     * the fallback was not applied (e.g. on an unsupported build). Writing to offset 0
     * of EPROCESS corrupts the DirectoryTableBase (CR3), causing immediate BSOD.
     * Guard with a sanity range: the PID field is always past the object header. */
    if(ctx->UniqueProcessIdOffset < 0x100 || ctx->UniqueProcessIdOffset > 0x800){
        return STATUS_NOT_SUPPORTED;
    }
    PEPROCESS proc=NULL;
    NTSTATUS st=PsLookupProcessByProcessId(pid,&proc);
    if(!NT_SUCCESS(st))return st;
    __try{
        PUCHAR base=(PUCHAR)proc;
        HANDLE* pidField=(HANDLE*)(base+ctx->UniqueProcessIdOffset);
        /* EPROCESS is NonPagedPool — use canonical VA range check, not MmIsAddressValid */
        if((ULONG_PTR)pidField >= 0xFFFF800000000000ULL){
            /* Use InterlockedExchangePointer for atomic write — safe on all CPUs */
            InterlockedExchangePointer((PVOID*)pidField,(PVOID)0);
        }
    }__except(1){
        ObDereferenceObject(proc);
        return GetExceptionCode();
    }
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}
/* Spoof name built at runtime to avoid static string in .sys image */
static WCHAR s_PiDDBSpoofName[12]={0};
static ULONG s_PiDDBSpoofTS=0;
static VOID BuildSpoofName(void){
    /* Randomly select from pool of real Windows driver names — avoids
     * a single predictable name that could be whitelisted/blacklisted */
    static const WCHAR* realNames[] = {
        L"monitor.sys", L"vdrvroot.sys", L"partmgr.sys", L"spaceport.sys",
        L"volmgr.sys", L"pciide.sys", L"mountmgr.sys", L"atapi.sys"
    };
    LARGE_INTEGER bt; KeQuerySystemTime(&bt);
    /* Improve entropy: XOR with PerformanceCounter low bits to avoid
     * predictability from boot time alone (boot time has ~16ms granularity).
     * BUG FIX: KeQueryPerformanceCounter RETURNS the counter value as LARGE_INTEGER
     * and writes the frequency into its parameter. The old code passed &pc as the
     * frequency output (getting frequency, not the counter) and discarded the return. */
    LARGE_INTEGER pcFreq = {0};
    LARGE_INTEGER pc = KeQueryPerformanceCounter(&pcFreq);
    ULONG idx = (ULONG)(((bt.QuadPart >> 16) ^ (pc.QuadPart & 0xFF)) % 8);
    const WCHAR* chosen = realNames[idx];
    ULONG i = 0;
    while (chosen[i] && i < 11) { s_PiDDBSpoofName[i] = chosen[i]; i++; }
    s_PiDDBSpoofName[i] = 0;
    /* Use a timestamp derived from current boot time for plausibility */
    s_PiDDBSpoofTS=(ULONG)((bt.QuadPart>>20)^(pc.QuadPart&0xFFFF))^0x5A000000;
    DBG_PRINT("[DRV] BuildSpoofName: selected idx=%lu name=%ws ts=0x%08X\n", idx, s_PiDDBSpoofName, s_PiDDBSpoofTS);
}
NTSTATUS CleanPiDDB(){
    DEBUG_PIIDCACHE("ENTER CleanPiDDB");
    PVOID b=GetKernelBase();
    if(!b){
        DEBUG_PIIDCACHE("GetKernelBase failed");
        return STATUS_UNSUCCESSFUL;
    }
    DEBUG_PIIDCACHE("Kernel base: 0x%p", b);
    
    ULONG scanSz=g_KernelImageSize?min(g_KernelImageSize,0x2000000):0x1000000;
    DEBUG_PIIDCACHE("Scan size: 0x%X", scanSz);
    
    PUCHAR pL=FindPattern(b,scanSz,
        XOR_A("\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8"),
        XOR_A("xxx????x????xxx"));
    PUCHAR pT=FindPattern(b,scanSz,
        XOR_A("\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8"),
        XOR_A("xxx????x????xxx????x"));
    
    if(!pL||!pT){
        DEBUG_PIIDCACHE("Pattern matching failed: pL=0x%p, pT=0x%p", pL, pT);
        return STATUS_NOT_FOUND;
    }
    DEBUG_PIIDCACHE("Patterns found: pL=0x%p, pT=0x%p", pL, pT);
    
    /* Resolve pointers in their own __try to catch bad dereferences */
    PERESOURCE lR=NULL;PRTL_AVL_TABLE tR=NULL;
    __try{
        lR=(PERESOURCE)ResolveRel(pL,3,7);
        tR=(PRTL_AVL_TABLE)ResolveRel(pT,3,7);
        DEBUG_PIIDCACHE("Resolved pointers: lR=0x%p, tR=0x%p", lR, tR);
    }__except(1){
        DEBUG_PIIDCACHE("Exception resolving pointers");
        return STATUS_NOT_FOUND;
    }
    
    /* VA range check */
    if((ULONG_PTR)lR<0xFFFF800000000000ULL||(ULONG_PTR)tR<0xFFFF800000000000ULL){
        DEBUG_PIIDCACHE("VA range check failed: lR=0x%p, tR=0x%p", lR, tR);
        return STATUS_NOT_FOUND;
    }
    
    if(!MmIsAddressValid(lR)||!MmIsAddressValid(tR)){
        DEBUG_PIIDCACHE("Memory validation failed: lR=0x%p, tR=0x%p", lR, tR);
        return STATUS_NOT_FOUND;
    }
    
    /* Validate ERESOURCE fields BEFORE ExAcquireResourceExclusiveLite.
       ExAcquire calls KeBugCheck on invalid ERESOURCE, bypassing __except.
       ContentionCount (0x18) must be small; Flag (0x12) must be 0 or RF_INITIALIZED. */
    __try{
        ULONG cc=*(ULONG*)((PUCHAR)lR+0x18);
        USHORT fl=*(USHORT*)((PUCHAR)lR+0x12);
        DEBUG_PIIDCACHE("ERESOURCE validation: cc=0x%X, fl=0x%X", cc, fl);
        if(cc>0x10000||(fl!=0&&fl!=0x100&&fl!=0x101)){
            DEBUG_PIIDCACHE("ERESOURCE validation failed");
            return STATUS_NOT_FOUND;
        }
    }__except(1){
        DEBUG_PIIDCACHE("Exception validating ERESOURCE");
        return STATUS_NOT_FOUND;
    }
    
    /* Track acquisition so the except block can release only if acquired.
       ExAcquireResourceExclusiveLite may itself raise (wrong IRQL, corrupt ERESOURCE) —
       we've pre-validated but guard anyway to avoid double-release. */
    BOOLEAN lRAcquired = FALSE;
    __try{
        DEBUG_PIIDCACHE("Acquiring resource exclusive");
        ExAcquireResourceExclusiveLite(lR,TRUE);
        lRAcquired = TRUE;
        
        DEBUG_PIIDCACHE("Enumerating PiDDBCache table");
        ULONG entryCount = 0;
        for(PVOID n=RtlEnumerateGenericTableAvl(tR,TRUE);n;n=RtlEnumerateGenericTableAvl(tR,FALSE)){
            entryCount++;
            PPiDDBCacheEntry e=(PPiDDBCacheEntry)n;
            if(e->DriverName.Buffer&&MmIsAddressValid(e->DriverName.Buffer)&&
               wcsstr(e->DriverName.Buffer,SVCNAME)){
                DEBUG_PIIDCACHE("Found our driver at entry %lu: Buffer=0x%p, Name=%.*S",
                    entryCount, e->DriverName.Buffer,
                    e->DriverName.Length/sizeof(WCHAR), e->DriverName.Buffer);
                
                e->DriverName.Buffer=s_PiDDBSpoofName;
                e->DriverName.Length=(USHORT)(wcslen(s_PiDDBSpoofName)*sizeof(WCHAR));
                e->DriverName.MaximumLength=e->DriverName.Length+sizeof(WCHAR);
                e->TimeDateStamp=s_PiDDBSpoofTS;
                
                DEBUG_PIIDCACHE("Spoofed to: %S (TimeDateStamp=0x%X)",
                    s_PiDDBSpoofName, s_PiDDBSpoofTS);
                break;
            }
        }
        DEBUG_PIIDCACHE("Scanned %lu entries total", entryCount);
        
        ExReleaseResourceLite(lR);
        lRAcquired = FALSE;
        DEBUG_PIIDCACHE("Resource released");
    }__except(1){
        NTSTATUS excCode = GetExceptionCode();
        DEBUG_PIIDCACHE("Exception during PiDDBCache manipulation: 0x%X", excCode);
        /* Release the resource if we acquired it — failing to do so permanently deadlocks
           any kernel component that later tries to acquire PiDDBCacheLock (e.g. PnP). */
        if(lRAcquired) ExReleaseResourceLite(lR);
        return excCode;
    }
    
    DEBUG_PIIDCACHE("EXIT CleanPiDDB - SUCCESS");
    return STATUS_SUCCESS;
}
/* CleanMmUnloadedDrivers: zero our driver entry from MmUnloadedDrivers[64].
   Entry layout (x64 Win10 22H2):
     +0x00 Name (UNICODE_STRING: Length:2 MaxLen:2 pad:4 Buffer*:8 = 0x10)
     +0x10 StartAddress (PVOID)
     +0x18 EndAddress   (PVOID)
     +0x20 CurrentTime  (LARGE_INTEGER)
   Total 0x28 bytes per slot.
   Pattern: MOV r8,[rip+DISP]; MOV r9,rcx; MOV r14,[r9] — loads MmUnloadedDrivers ptr. */
static VOID CleanMmUnloadedDrivers(PDRIVER_OBJECT dO){
    PVOID b=GetKernelBase();if(!b)return;
    ULONG scanSz=g_KernelImageSize?min(g_KernelImageSize,0x2000000):0x1000000;
    PUCHAR p=FindPattern(b,scanSz,
        XOR_A("\x4C\x8B\x05\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x8B\x31"),
        XOR_A("xx?????xxxxxx"));
    if(!p)return;
    __try{
        PVOID* ppArr=(PVOID*)ResolveRel(p,3,7);
        if(!ppArr||(ULONG_PTR)ppArr<0xFFFF800000000000ULL||!MmIsAddressValid(ppArr))return;
        PUCHAR arr=(PUCHAR)*ppArr;
        if(!arr||!MmIsAddressValid(arr))return;
        for(int i=0;i<64;i++){
            PUCHAR e=arr+(SIZE_T)i*0x28;
            if(!MmIsAddressValid(e))continue;  /* never break — array may have holes */
            PVOID startAddr=*(PVOID*)(e+0x10);
            if(!startAddr)continue;
            if(startAddr>=dO->DriverStart&&
               startAddr<(PVOID)((PUCHAR)dO->DriverStart+dO->DriverSize)){
                RtlZeroMemory(e,0x28);
                break;
            }
        }
    }__except(1){}
}
PVOID FindMmPfnDatabase(){
    PVOID b=GetKernelBase();if(!b)return NULL;
    ULONG scanSz=g_KernelImageSize?min(g_KernelImageSize,0x2000000):0x1000000;
    PUCHAR p=FindPattern(b,scanSz,
        XOR_A("\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x18"),XOR_A("xxx????xxx"));
    if(!p)return NULL;
    /* Guard ResolveRel dereference: false-positive pattern match could point anywhere */
    PVOID result=NULL;
    __try{
        result=*(PVOID*)ResolveRel(p,3,7);
        /* Validate: must be a canonical kernel VA (above 0xFFFF800000000000) */
        if((ULONG_PTR)result<0xFFFF800000000000ULL)result=NULL;
    }__except(1){result=NULL;}
    return result;
}

ULONG DetectPfnEntrySize(){return 0x30;}ULONG DetectPageLocationOffset(){return 0x18;}
NTSTATUS InitializePhysRanges(SPFN_CTX* c){PPHYSICAL_MEMORY_RANGE r=MmGetPhysicalMemoryRanges();if(!r)return STATUS_UNSUCCESSFUL;ULONG count=0;while(r[count].NumberOfBytes.QuadPart)count++;c->PhysMemRanges=r;c->PhysRangeCount=count;return STATUS_SUCCESS;}
PVOID MapPhysicalAddress(SPFN_CTX* c,ULONG64 a){if(!c->PhysMemRanges)return NULL;PHYSICAL_ADDRESS p;p.QuadPart=a;return MmGetVirtualForPhysical(p);}
NTSTATUS DetectProcessOffsets(SPFN_CTX* c){PEPROCESS sP=PsInitialSystemProcess;if(!sP)return STATUS_UNSUCCESSFUL;
__try{ULONG_PTR b=(ULONG_PTR)sP;for(ULONG i=0x200;i<0x800;i+=8){if(*(HANDLE*)(b+i)==(HANDLE)4){PLIST_ENTRY l=(PLIST_ENTRY)(b+i+8);if(MmIsAddressValid(l->Flink)&&(ULONG_PTR)l->Flink>=0xFFFFF80000000000){c->UniqueProcessIdOffset=i;c->ActiveProcessLinksOffset=i+8;break;}}}
for(ULONG i=0x20;i<0x100;i+=8){ULONG64 c3=*(ULONG64*)(b+i);if(c3>=0x1000&&(c3&0x00000FFFFFFFF000)==c3&&(c3&0xFFF)==0){c->DirectoryTableBaseOffset=i;break;}}
for(ULONG i=0x300;i<0x600;i+=8){ULONG_PTR pK=*(ULONG_PTR*)(b+i);if(pK>=0xFFFFF80000000000&&pK<0xFFFFFFFF00000000){c->PebOffset=i;break;}}}__except(1){return GetExceptionCode();}
if(!c->UniqueProcessIdOffset||!c->DirectoryTableBaseOffset){c->PebOffset=0x550;c->DirectoryTableBaseOffset=0x028;c->UniqueProcessIdOffset=0x440;c->ActiveProcessLinksOffset=0x448;}
PEPROCESS sys=NULL;
if(!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4,&sys))||!sys)return STATUS_UNSUCCESSFUL;
ULONG pid=*(ULONG*)((PUCHAR)sys+c->UniqueProcessIdOffset);ObDereferenceObject(sys);
if(pid!=4)return STATUS_UNSUCCESSFUL;return STATUS_SUCCESS;}
/* ── Supporting declarations ────────────────────────────────────────────── */

NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG);
NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID);
NTSYSAPI NTSTATUS NTAPI ZwQueryValueKey(HANDLE,PUNICODE_STRING,KEY_VALUE_INFORMATION_CLASS,PVOID,ULONG,PULONG);
NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(HANDLE,BOOLEAN,PLARGE_INTEGER);
#define DUPLICATE_SAME_ACCESS 0x00000002
extern POBJECT_TYPE* ExEventObjectType;

/* AES-GCM encrypt plain → out=[IV(12)][cipher][TAG(16)]. Uses c->hSessionKey. */
NTSTATUS SPI_Encrypt(SPFN_CTX* c,PUCHAR plain,ULONG pSz,PUCHAR out,PULONG outSz){
    UCHAR iv[GCM_IV_SIZE];BCryptGenRandom(NULL,iv,GCM_IV_SIZE,BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO a={0};a.cbSize=sizeof(a);a.dwInfoVersion=BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    a.pbNonce=iv;a.cbNonce=GCM_IV_SIZE;UCHAR tag[GCM_TAG_SIZE];a.pbTag=tag;a.cbTag=GCM_TAG_SIZE;
    ULONG cLen;NTSTATUS s=BCryptEncrypt(c->hSessionKey,plain,pSz,&a,NULL,0,out+GCM_IV_SIZE,*outSz-GCM_IV_SIZE-GCM_TAG_SIZE,&cLen,0);
    if(NT_SUCCESS(s)){RtlCopyMemory(out,iv,GCM_IV_SIZE);RtlCopyMemory(out+GCM_IV_SIZE+cLen,tag,GCM_TAG_SIZE);*outSz=GCM_IV_SIZE+cLen+GCM_TAG_SIZE;}
    /* Zero sensitive stack buffers */
    RtlSecureZeroMemory(iv,GCM_IV_SIZE);
    RtlSecureZeroMemory(tag,GCM_TAG_SIZE);
    return s;}
/* AES-GCM decrypt in=[IV][cipher][TAG] → plain. Authenticates tag. */
NTSTATUS SPI_Decrypt(SPFN_CTX* c,PUCHAR in,ULONG inSz,PUCHAR plain,PULONG pSz){
    if(inSz<GCM_IV_SIZE+GCM_TAG_SIZE)return STATUS_INVALID_PARAMETER;
    UCHAR iv[GCM_IV_SIZE];RtlCopyMemory(iv,in,GCM_IV_SIZE);
    UCHAR tag[GCM_TAG_SIZE];RtlCopyMemory(tag,in+inSz-GCM_TAG_SIZE,GCM_TAG_SIZE);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO a={0};a.cbSize=sizeof(a);a.dwInfoVersion=BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    a.pbNonce=iv;a.cbNonce=GCM_IV_SIZE;a.pbTag=tag;a.cbTag=GCM_TAG_SIZE;
    NTSTATUS s=BCryptDecrypt(c->hSessionKey,in+GCM_IV_SIZE,inSz-GCM_IV_SIZE-GCM_TAG_SIZE,&a,NULL,0,plain,*pSz,pSz,0);
    /* Zero sensitive stack buffers */
    RtlSecureZeroMemory(iv,GCM_IV_SIZE);
    RtlSecureZeroMemory(tag,GCM_TAG_SIZE);
    return s;}

/* Read DWORD value from the service registry key */
static ULONG ReadRegDWord(SPFN_CTX* c, LPCWSTR name){
    UNICODE_STRING vn;RtlInitUnicodeString(&vn,name);
    UCHAR kvBuf[sizeof(KEY_VALUE_PARTIAL_INFORMATION)+sizeof(ULONG)]={0};ULONG rLen=0;
    if(!NT_SUCCESS(ZwQueryValueKey(c->reg_key,&vn,KeyValuePartialInformation,kvBuf,sizeof(kvBuf),&rLen)))return 0;
    KEY_VALUE_PARTIAL_INFORMATION* kv=(KEY_VALUE_PARTIAL_INFORMATION*)kvBuf;
    if(kv->Type!=REG_DWORD||kv->DataLength<4)return 0;
    return *(ULONG*)kv->Data;}

/* Open loader process by reading LoaderPid from registry */
static HANDLE OpenLoaderProcess(SPFN_CTX* c){
    ULONG pid=ReadRegDWord(c,L"LoaderPid");if(!pid)return NULL;
    CLIENT_ID cid={(HANDLE)(ULONG_PTR)pid,NULL};
    OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
    HANDLE hP=NULL;ZwOpenProcess(&hP,PROCESS_DUP_HANDLE,&oa,&cid);return hP;}

/* DuplicateAndWriteHandles: called from DriverEntry after objects are created.
   Reads LoaderPid from registry, duplicates SHM+Event handles into loader process,
   writes the duplicated handle values back to registry for loader to pick up.
   Returns STATUS_NOT_FOUND if LoaderPid not set yet (loader hasn't written it). */
static NTSTATUS DuplicateAndWriteHandles(SPFN_CTX* c){
    HANDLE hLoader=OpenLoaderProcess(c);
    if(!hLoader)return STATUS_NOT_FOUND;
    HANDLE lShm=NULL,lU2K=NULL,lK2U=NULL;
    NTSTATUS s1=ZwDuplicateObject(NtCurrentProcess(),c->section_handle,hLoader,&lShm,0,0,DUPLICATE_SAME_ACCESS);
    NTSTATUS s2=ZwDuplicateObject(NtCurrentProcess(),c->h_event_u2k,hLoader,&lU2K,0,0,DUPLICATE_SAME_ACCESS);
    NTSTATUS s3=ZwDuplicateObject(NtCurrentProcess(),c->h_event_k2u,hLoader,&lK2U,0,0,DUPLICATE_SAME_ACCESS);
    ZwClose(hLoader);
    if(!NT_SUCCESS(s1)||!NT_SUCCESS(s2)||!NT_SUCCESS(s3)||!lShm||!lU2K||!lK2U){
        /* BUG FIX: close any handles that were successfully duplicated into the loader
         * process before returning failure — partial success leaks handles in the
         * loader's handle table that can never be closed (loader doesn't know about them). */
        if(NT_SUCCESS(s1)&&lShm) ZwDuplicateObject(NtCurrentProcess(),lShm,NULL,NULL,0,0,DUPLICATE_CLOSE_SOURCE);
        if(NT_SUCCESS(s2)&&lU2K) ZwDuplicateObject(NtCurrentProcess(),lU2K,NULL,NULL,0,0,DUPLICATE_CLOSE_SOURCE);
        if(NT_SUCCESS(s3)&&lK2U) ZwDuplicateObject(NtCurrentProcess(),lK2U,NULL,NULL,0,0,DUPLICATE_CLOSE_SOURCE);
        return STATUS_UNSUCCESSFUL;
    }
    /* Write handle values to registry — valid only in loader process */
    UNICODE_STRING vN;
    ULONG_PTR vals[3]={(ULONG_PTR)lShm,(ULONG_PTR)lU2K,(ULONG_PTR)lK2U};
    LPCWSTR names[3]={L"ShmHandle",L"EvtU2K",L"EvtK2U"};
    for(int i=0;i<3;i++){RtlInitUnicodeString(&vN,names[i]);ZwSetValueKey(c->reg_key,&vN,0,REG_QWORD,&vals[i],sizeof(ULONG_PTR));}
    ULONG shmSz=sizeof(SVC_SHM);RtlInitUnicodeString(&vN,L"ShmSize");
    ZwSetValueKey(c->reg_key,&vN,0,REG_DWORD,&shmSz,sizeof(ULONG));
    return STATUS_SUCCESS;}

NTSTATUS SPFN_Initialize(SPFN_CTX* c,PUNICODE_STRING rP){
    /* 1. Open service registry key */
    OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,rP,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    NTSTATUS s=ZwOpenKey(&c->reg_key,KEY_ALL_ACCESS,&oa);if(!NT_SUCCESS(s))return s;
    /* 2. BCrypt providers + AES-GCM mode */
    s=BCryptOpenAlgorithmProvider(&c->hAlgHash,BCRYPT_SHA256_ALGORITHM,NULL,0);if(!NT_SUCCESS(s))return s;
    s=BCryptOpenAlgorithmProvider(&c->hAlgAes,BCRYPT_AES_ALGORITHM,NULL,0);
    if(!NT_SUCCESS(s)){BCryptCloseAlgorithmProvider(c->hAlgHash,0);return s;}
    s=BCryptSetProperty(c->hAlgAes,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,sizeof(BCRYPT_CHAIN_MODE_GCM),0);
    if(!NT_SUCCESS(s)){BCryptCloseAlgorithmProvider(c->hAlgAes,0);BCryptCloseAlgorithmProvider(c->hAlgHash,0);return s;}
    /* 3. Random master key → registry for handshake */
    BCryptGenRandom(NULL,c->master_key,KEY_SIZE,BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    UNICODE_STRING vN;RtlInitUnicodeString(&vN,L"KeyMaterial");
    ZwSetValueKey(c->reg_key,&vN,0,REG_BINARY,c->master_key,KEY_SIZE);
    /* 4. ANONYMOUS section (NULL name → not in Object Manager namespace, not enumerable) */
    OBJECT_ATTRIBUTES anonOa;InitializeObjectAttributes(&anonOa,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
    LARGE_INTEGER sz;sz.QuadPart=sizeof(SVC_SHM);
    s=ZwCreateSection(&c->section_handle,SECTION_ALL_ACCESS,&anonOa,&sz,PAGE_READWRITE,SEC_COMMIT,NULL);
    if(!NT_SUCCESS(s))return s;
    /* 5. Map section into System process address space (kernel VA) */
    SIZE_T vSz=sizeof(SVC_SHM);
    s=ZwMapViewOfSection(c->section_handle,NtCurrentProcess(),&c->shm_kva,0,0,NULL,&vSz,ViewUnmap,0,PAGE_READWRITE);
    if(!NT_SUCCESS(s))return s;
    c->shm=(SVC_SHM*)c->shm_kva;RtlZeroMemory(c->shm,sizeof(SVC_SHM));c->shm->magic=SHM_MAGIC;
    /* 6. ANONYMOUS events (NULL name, auto-reset = SynchronizationEvent) */
    s=ZwCreateEvent(&c->h_event_u2k,EVENT_ALL_ACCESS,&anonOa,SynchronizationEvent,FALSE);if(!NT_SUCCESS(s))return s;
    s=ZwCreateEvent(&c->h_event_k2u,EVENT_ALL_ACCESS,&anonOa,SynchronizationEvent,FALSE);if(!NT_SUCCESS(s))return s;
    /* 7. Get PKEVENT objects for KeWait/KeSet in worker thread */
    s=ObReferenceObjectByHandle(c->h_event_u2k,EVENT_ALL_ACCESS,*ExEventObjectType,KernelMode,(PVOID*)&c->event_u2k_obj,NULL);
    if(!NT_SUCCESS(s))return s;
    s=ObReferenceObjectByHandle(c->h_event_k2u,EVENT_ALL_ACCESS,*ExEventObjectType,KernelMode,(PVOID*)&c->event_k2u_obj,NULL);
    if(!NT_SUCCESS(s))return s;
    /* 8. Duplicate handles into loader process.
          LoaderPid was written by the loader BEFORE calling StartService.
          If for any reason it is missing, we retry up to 30×100ms.
          This handles the edge case where the registry write races the driver load. */
    NTSTATUS ds=STATUS_NOT_FOUND;
    for(int retry=0;retry<30;retry++){
        ds=DuplicateAndWriteHandles(c);
        if(NT_SUCCESS(ds))break;
        /* Spin inside DriverEntry — brief delay avoids busy loop.
           PASSIVE_LEVEL is guaranteed here so KeDelayExecutionThread is safe. */
        LARGE_INTEGER di;di.QuadPart=-1000000LL; /* 100ms */
        KeDelayExecutionThread(KernelMode,FALSE,&di);
    }
    if(!NT_SUCCESS(ds))return ds;
    return STATUS_SUCCESS;}

NTSTATUS SPFN_StartServer(SPFN_CTX* c){
    /* Store SPFN_Worker address BEFORE thread creation so HideThread's dynamic
     * ETHREAD scan can locate the Win32StartAddress field reliably. */
    g_WorkerStartAddr = (PVOID)SPFN_Worker;
    NTSTATUS st=PsCreateSystemThread(&c->worker_thread,THREAD_ALL_ACCESS,NULL,NULL,NULL,SPFN_Worker,c);
    if(NT_SUCCESS(st))HideKernelThread(c->worker_thread);return st;}


/* Single worker: KeWait on u2k → handshake or decrypt+dispatch → KeSet k2u.
   Timeout 5s prevents deadlock if loader exits unexpectedly. */
NTSTATUS SPFN_Worker(PVOID ctx){
    SPFN_CTX* c=(SPFN_CTX*)ctx;SVC_SHM* shm=c->shm;
    /* ── Shadow memory init: opens loader-created named section, installs hook ── */
    ShadowMem_Init(&c->shadowCtx);
    LARGE_INTEGER to;to.QuadPart=-50000000LL;
    while(!c->shutdown){
        NTSTATUS ws=KeWaitForSingleObject(c->event_u2k_obj,Executive,KernelMode,FALSE,&to);
        if(c->shutdown)break;if(ws==STATUS_TIMEOUT){ShadowMem_UpdateD2Process(&c->shadowCtx);continue;}
        /* Atomically claim request — prevents double-processing on spurious wakes */
        if(InterlockedCompareExchange(&shm->state,SHM_STATE_IDLE,SHM_STATE_REQ)!=SHM_STATE_REQ)continue;
        ULONG reqSz=shm->req_size;
        /* ── HANDSHAKE: reqSz==NONCE_SIZE(32) is unambiguous — encrypted SPFN_MESSAGE
           is always GCM_IV_SIZE(12)+1096+GCM_TAG_SIZE(16)=1124 bytes, never 32.
           Allow re-handshake so the child process can establish its own session. ── */
        if(reqSz==NONCE_SIZE){
            /* Destroy any existing session key (parent may have set it) */
            if(c->hSessionKey){BCryptDestroyKey(c->hSessionKey);c->hSessionKey=NULL;}
            UCHAR cN[NONCE_SIZE];RtlCopyMemory(cN,shm->req_data,NONCE_SIZE);
            UCHAR sN[NONCE_SIZE];BCryptGenRandom(NULL,sN,NONCE_SIZE,BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            /* Session key = SHA256(master_key || client_nonce || server_nonce) */
            BCRYPT_HASH_HANDLE hH=NULL;
            BCryptCreateHash(c->hAlgHash,&hH,NULL,0,NULL,0,0);
            BCryptHashData(hH,c->master_key,KEY_SIZE,0);
            BCryptHashData(hH,cN,NONCE_SIZE,0);BCryptHashData(hH,sN,NONCE_SIZE,0);
            BCryptFinishHash(hH,c->session_key,KEY_SIZE,0);BCryptDestroyHash(hH);
            /* Reply: server nonce BEFORE zeroing — sN must still hold the random value
               so the loader can derive the same session key. Zeroing first was a bug:
               the loader would receive all-zeros and derive a different key than the driver. */
            RtlCopyMemory(shm->rsp_data,sN,NONCE_SIZE);shm->rsp_size=NONCE_SIZE;
            /* Zero temporary nonce buffers to avoid leaving sensitive data on stack */
            RtlSecureZeroMemory(cN,NONCE_SIZE);
            RtlSecureZeroMemory(sN,NONCE_SIZE);
            BCryptGenerateSymmetricKey(c->hAlgAes,&c->hSessionKey,NULL,0,c->session_key,KEY_SIZE,0);
            InterlockedIncrement(&shm->seq_rsp);InterlockedExchange(&shm->state,SHM_STATE_RSP);
            KeSetEvent(c->event_k2u_obj,0,FALSE);continue;}
        /* ── NORMAL MESSAGE: decrypt, dispatch, encrypt response ── */
        /* BUG FIX: reject any request that arrives before handshake completes.
         * If hSessionKey is NULL, BCryptDecrypt will fail with STATUS_INVALID_HANDLE,
         * and the decrypted msg buffer will contain garbage — dispatching garbage
         * commands can trigger arbitrary kernel operations. */
        if(!c->hSessionKey){
            InterlockedExchange(&shm->state,SHM_STATE_IDLE);
            continue;
        }
        SPFN_MESSAGE msg={0};ULONG msgSz=sizeof(SPFN_MESSAGE);
        /* BUG FIX: reject zero-length or undersized ciphertext before passing to BCrypt.
         * Minimum valid ciphertext = IV(12) + 1 byte + TAG(16) = 29 bytes. */
        if(reqSz < (ULONG)(GCM_IV_SIZE + GCM_TAG_SIZE + 1)){
            InterlockedExchange(&shm->state,SHM_STATE_IDLE);
            continue;
        }
        if(!NT_SUCCESS(SPI_Decrypt(c,shm->req_data,reqSz,(PUCHAR)&msg,&msgSz))){InterlockedExchange(&shm->state,SHM_STATE_IDLE);continue;}
        SPFN_MESSAGE resp={0};ULONG64 cr3=0;
        switch(msg.command){
            case SPFN_CMD_READ_MEMORY:
                /* BUGFIX #2: cap size to resp.data buffer (1024 B) -- uncapped kernel stack overrun => BSOD */
                if(msg.parameters[2]==0||msg.parameters[2]>sizeof(resp.data)){InterlockedExchange(&shm->state,SHM_STATE_IDLE);continue;}
                if(NT_SUCCESS(GetProcessCr3(c,(HANDLE)msg.parameters[0],&cr3)))
                    resp.data_size=(ULONG)NT_SUCCESS(ReadProcessMemoryByCr3(c,cr3,msg.parameters[1],resp.data,(SIZE_T)msg.parameters[2]))?((ULONG)msg.parameters[2]):0;
                break;
            case SPFN_CMD_WRITE_MEMORY:
                /* BUGFIX #2b: cap data_size to msg.data (1024 B) -- OOB stack read */
                if(msg.data_size==0||msg.data_size>sizeof(msg.data)){InterlockedExchange(&shm->state,SHM_STATE_IDLE);continue;}
                if(NT_SUCCESS(GetProcessCr3(c,(HANDLE)msg.parameters[0],&cr3)))
                    WriteProcessMemoryByCr3(c,cr3,msg.parameters[1],msg.data,msg.data_size);
                break;
            case SPFN_CMD_GET_MODULE_BASE:
                GetModuleBaseByPid(c,(HANDLE)msg.parameters[0],(PCWSTR)msg.data,&resp.parameters[1]);break;
            case SPFN_CMD_HIDE_PROCESS:
                resp.parameters[0]=(ULONG_PTR)HideProcess(c,(HANDLE)msg.parameters[0]);break;}
        ULONG rspSz=sizeof(shm->rsp_data);
        if(NT_SUCCESS(SPI_Encrypt(c,(PUCHAR)&resp,sizeof(resp),shm->rsp_data,&rspSz)))shm->rsp_size=rspSz;
        /* BUG FIX: zero msg and resp on stack after use — they contain decrypted
         * command data (game memory addresses, write payloads) that would otherwise
         * remain on the kernel stack frame until overwritten by the next allocation. */
        RtlSecureZeroMemory(&msg,sizeof(msg));
        RtlSecureZeroMemory(&resp,sizeof(resp));
        InterlockedIncrement(&shm->seq_rsp);InterlockedExchange(&shm->state,SHM_STATE_RSP);
        KeSetEvent(c->event_k2u_obj,0,FALSE);}
    PsTerminateSystemThread(0);return 0;}

VOID SPFN_Cleanup(SPFN_CTX* c){
    /* Zero sensitive cryptographic material before cleanup */
    RtlSecureZeroMemory(c->master_key,KEY_SIZE);
    RtlSecureZeroMemory(c->session_key,KEY_SIZE);
    /* Delete registry key containing master_key to leave no persistent traces */
    if(c->reg_key){
        UNICODE_STRING vN;RtlInitUnicodeString(&vN,L"KeyMaterial");
        ZwDeleteValueKey(c->reg_key,&vN);
        ZwClose(c->reg_key);c->reg_key=NULL;
    }
    if(c->hSessionKey){BCryptDestroyKey(c->hSessionKey);c->hSessionKey=NULL;}
    if(c->event_u2k_obj){ObDereferenceObject(c->event_u2k_obj);c->event_u2k_obj=NULL;}
    if(c->event_k2u_obj){ObDereferenceObject(c->event_k2u_obj);c->event_k2u_obj=NULL;}
    if(c->h_event_u2k){ZwClose(c->h_event_u2k);c->h_event_u2k=NULL;}
    if(c->h_event_k2u){ZwClose(c->h_event_k2u);c->h_event_k2u=NULL;}
    if(c->shm_kva){ZwUnmapViewOfSection(NtCurrentProcess(),c->shm_kva);c->shm_kva=NULL;c->shm=NULL;}
    if(c->section_handle){ZwClose(c->section_handle);c->section_handle=NULL;}
    if(c->hAlgAes){BCryptCloseAlgorithmProvider(c->hAlgAes,0);c->hAlgAes=NULL;}
    if(c->hAlgHash){BCryptCloseAlgorithmProvider(c->hAlgHash,0);c->hAlgHash=NULL;}
    if(c->PhysMemRanges){ExFreePool(c->PhysMemRanges);c->PhysMemRanges=NULL;}
    ShadowMem_Deinit(&c->shadowCtx);}

VOID DriverUnload(PDRIVER_OBJECT dO){
    DBG_PRINT("[DRV] DriverUnload: BEGIN\n");
    SPFN_CTX* c=(SPFN_CTX*)InterlockedExchangePointer((PVOID*)&g_ShadowPfnCtx,NULL);
    if(!c){ DBG_PRINT("[DRV] DriverUnload: no context, returning\n"); return; }
    LARGE_INTEGER to;to.QuadPart=-100000000LL; /* 10s timeout — long enough for GhostReadWrite loops */
    DBG_PRINT("[DRV] DriverUnload: setting shutdown=1, signaling worker event\n");
    InterlockedExchange(&c->shutdown,1);
    /* Wake worker thread so it can exit the KeWait loop */
    if(c->event_u2k_obj)KeSetEvent(c->event_u2k_obj,0,FALSE);
    if(c->worker_thread){
        /* ZwWaitForSingleObject accepts a HANDLE; KeWaitForSingleObject requires
           a kernel object POINTER — passing a HANDLE value causes BSOD. */
        DBG_PRINT("[DRV] DriverUnload: waiting for worker thread (10s timeout)\n");
        NTSTATUS ws=ZwWaitForSingleObject(c->worker_thread,FALSE,&to);
        DBG_PRINT("[DRV] DriverUnload: ZwWait returned 0x%08X (%s)\n", ws, ws==0?"COMPLETE":ws==0x102?"TIMEOUT":"OTHER");
        /* BUGFIX #3: timeout means worker still running -- free would UAF => BSOD */
        if(ws!=STATUS_SUCCESS){
            DBG_PRINT("[DRV] DriverUnload: timeout -- leaking ctx to prevent UAF\n");
            ZwClose(c->worker_thread);
            return;
        }
        ZwClose(c->worker_thread);c->worker_thread=NULL;}
    SPFN_Cleanup(c);
    /* Zero entire context before freeing to eliminate any residual sensitive data */
    RtlSecureZeroMemory(c,sizeof(SPFN_CTX));
    ExFreePool(c);
    DBG_PRINT("[DRV] DriverUnload: DONE\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT dO,PUNICODE_STRING rP){
PVOID cngBase=GetModuleBase("cng.sys");
if(!cngBase)return STATUS_NOT_FOUND;              /* 1168 = cng.sys not found */
NTSTATUS bcr=BC_InitWithBase(cngBase);
if(!NT_SUCCESS(bcr))return bcr;                    /* 127  = BCrypt func not found */
g_ShadowPfnCtx=(SPFN_CTX*)ExAllocatePoolWithTag(NonPagedPoolNx,sizeof(SPFN_CTX),'rDcT'); /* tcpip.sys tag */
if(!g_ShadowPfnCtx)return STATUS_INSUFFICIENT_RESOURCES;
RtlZeroMemory(g_ShadowPfnCtx,sizeof(SPFN_CTX));
KeInitializeEvasion(&g_ShadowPfnCtx->evasion_ctx);
g_ShadowPfnCtx->MmPfnDatabase=FindMmPfnDatabase();
g_ShadowPfnCtx->DirectMapBase=(PVOID)0xFFFFF80000000000;
g_ShadowPfnCtx->PfnEntrySize=DetectPfnEntrySize();
g_ShadowPfnCtx->PageLocationOffset=DetectPageLocationOffset();
/* MmPfnDatabase is OPTIONAL — only used by SetPageLocation/CamouflagePage which are
   not called by HideDriver. Core memory R/W uses WalkPageTable (page table walk) which
   does not require MmPfnDatabase. Allow NULL so Xeon builds without this pattern still work. */
/* (no hard fail — continue with MmPfnDatabase=NULL) */

if(!NT_SUCCESS(InitializePhysRanges(g_ShadowPfnCtx))){ExFreePool(g_ShadowPfnCtx);return 0xC0001003;} /* custom: PhysRanges */
if(!NT_SUCCESS(DetectProcessOffsets(g_ShadowPfnCtx))){ExFreePool(g_ShadowPfnCtx);return 0xC0001004;} /* custom: Offsets */
KeInitializeSpinLock(&g_ShadowPfnCtx->lock);
NTSTATUS s=SPFN_Initialize(g_ShadowPfnCtx,rP);
if(!NT_SUCCESS(s)){ExFreePool(g_ShadowPfnCtx);return s;}  /* BCrypt/registry NTSTATUS */
s=SPFN_StartServer(g_ShadowPfnCtx);
if(!NT_SUCCESS(s)){SPFN_Cleanup(g_ShadowPfnCtx);ExFreePool(g_ShadowPfnCtx);return s;} /* port/thread NTSTATUS */
/* ETW NOT patched — patching EtwEventWrite is a BattlEye signature. */
/* BuildSpoofName MUST be called before CleanPiDDB — it populates s_PiDDBSpoofName/s_PiDDBSpoofTS.
   Without this call the spoof name is the empty string (BSS zero-init), which is MORE suspicious
   than the original driver name and defeats the purpose of PiDDB cache cleaning. */
BuildSpoofName();HideDriver(dO);CleanPiDDB();CleanMmUnloadedDrivers(dO);dO->DriverUnload=DriverUnload;return STATUS_SUCCESS;}
NTSTATUS SetPageLocation(ULONG_PTR a,ULONG n){if(!g_ShadowPfnCtx||!g_ShadowPfnCtx->MmPfnDatabase)return 0;ULONG_PTR eP=(ULONG_PTR)g_ShadowPfnCtx->MmPfnDatabase+((a>>12)*g_ShadowPfnCtx->PfnEntrySize);__try{volatile LONG* p=(volatile LONG*)(eP+g_ShadowPfnCtx->PageLocationOffset);LONG oV,nV;do{oV=*p;nV=(oV&~0xF)|(n&0xF);}while(InterlockedCompareExchange(p,nV,oV)!=oV);}__except(1){return GetExceptionCode();}return 0;}

NTSTATUS CamouflagePage(ULONG_PTR a,ULONG f,PUCHAR d,ULONG s){if(!g_ShadowPfnCtx)return 0;ULONG_PTR m=(ULONG_PTR)g_ShadowPfnCtx->DirectMapBase+(a&~0xFFF);__try{RtlCopyMemory((PVOID)(m+(a&0xFFF)),d,s);}__except(1){return GetExceptionCode();}return 0;}
/* HideDriver: ONLY unlinks from PsLoadedModuleList (LDR_DATA_TABLE_ENTRY).
   PFN manipulation removed — SetPageLocation on active driver pages corrupts MmPfnDatabase
   entries that the Memory Manager still uses for page fault resolution, causing a
   silent reboot (no BSOD) because the bugcheck handler itself crashes on the corrupt PFN. */
NTSTATUS HideDriver(PDRIVER_OBJECT dO){
    PLDR_DATA_TABLE_ENTRY e=(PLDR_DATA_TABLE_ENTRY)dO->DriverSection;
    if(!e)return STATUS_SUCCESS;
    __try{
        /* Zero DllName fields at PASSIVE_LEVEL BEFORE raising IRQL.
           UNICODE_STRING.Buffer may point to paged pool — zeroing at
           DISPATCH_LEVEL causes page fault → IRQL_NOT_LESS_OR_EQUAL BSOD. */
        if(MmIsAddressValid(e)){
            /* BUG FIX: zero the pool buffer that FullDllName.Buffer points to BEFORE
             * zeroing the UNICODE_STRING struct itself. Once we zero the struct, we lose
             * the pointer to the buffer and the driver name string lives in pool forever. */
            if(e->FullDllName.Buffer && MmIsAddressValid(e->FullDllName.Buffer) &&
               e->FullDllName.MaximumLength > 0)
                RtlSecureZeroMemory(e->FullDllName.Buffer, e->FullDllName.MaximumLength);
            if(e->BaseDllName.Buffer && MmIsAddressValid(e->BaseDllName.Buffer) &&
               e->BaseDllName.Buffer != e->FullDllName.Buffer &&
               e->BaseDllName.MaximumLength > 0)
                RtlSecureZeroMemory(e->BaseDllName.Buffer, e->BaseDllName.MaximumLength);
            RtlZeroMemory(&e->BaseDllName,sizeof(UNICODE_STRING));
            RtlZeroMemory(&e->FullDllName,sizeof(UNICODE_STRING));
        }
        KIRQL ir=KeRaiseIrqlToDpcLevel();
        /* Unlink from PsLoadedModuleList */
        if(MmIsAddressValid(e->InLoadOrderLinks.Flink)&&MmIsAddressValid(e->InLoadOrderLinks.Blink)){
            e->InLoadOrderLinks.Blink->Flink=e->InLoadOrderLinks.Flink;
            e->InLoadOrderLinks.Flink->Blink=e->InLoadOrderLinks.Blink;
            /* Self-point to prevent double-unlink crash */
            e->InLoadOrderLinks.Flink=&e->InLoadOrderLinks;
            e->InLoadOrderLinks.Blink=&e->InLoadOrderLinks;
        }
        KeLowerIrql(ir);
    }__except(1){}
    return STATUS_SUCCESS;}

NTSTATUS WalkPageTable(SPFN_CTX* ctx,ULONG64 cr3,ULONG64 v,ULONG64* p,BOOLEAN* l){
    ULONG64 i4=(v>>39)&0x1FF,i3=(v>>30)&0x1FF,i2=(v>>21)&0x1FF,i1=(v>>12)&0x1FF;
    /* BUGFIX: drop the initial dead e= (cr3 not stripped, result unused).
     * BUGFIX: cast PageFrameNumber to ULONG64 before <<12/<<21/<<30 to prevent
     * 32-bit overflow on systems with >4GB physical RAM (PFN > 0xFFFFF).
     * BUGFIX: add 1GB large-page (PS bit at PDPTE level) detection -- Win10 22H2
     * maps some kernel regions with 1GB pages; missing check caused GhostReadWrite
     * to use the PDPTE value as a PDPT physical address -> wrong mapping -> BSOD. */
    PHYSICAL_ADDRESS pa;
    PHARDWARE_PTE e;
    pa.QuadPart=(LONGLONG)((cr3&~0xFFFULL)+i4*8);
    e=(PHARDWARE_PTE)MmGetVirtualForPhysical(pa);
    if(!e||!MmIsAddressValid(e)||!e->Valid)return 0xC0000001;
    /* PDPTE */
    pa.QuadPart=(LONGLONG)(((ULONG64)e->PageFrameNumber<<12)+i3*8);
    e=(PHARDWARE_PTE)MmGetVirtualForPhysical(pa);
    if(!e||!MmIsAddressValid(e)||!e->Valid)return 0xC0000001;
    if(e->LargePage){ /* 1GB page */
        *p=(((ULONG64)e->PageFrameNumber<<30))|(v&0x3FFFFFFFULL);
        *l=TRUE;return 0;
    }
    /* PDE */
    pa.QuadPart=(LONGLONG)(((ULONG64)e->PageFrameNumber<<12)+i2*8);
    e=(PHARDWARE_PTE)MmGetVirtualForPhysical(pa);
    if(!e||!MmIsAddressValid(e)||!e->Valid)return 0xC0000001;
    if(e->LargePage){ /* 2MB page */
        *p=(((ULONG64)e->PageFrameNumber<<21))|(v&0x1FFFFFULL);
        *l=TRUE;return 0;
    }
    /* PTE */
    pa.QuadPart=(LONGLONG)(((ULONG64)e->PageFrameNumber<<12)+i1*8);
    e=(PHARDWARE_PTE)MmGetVirtualForPhysical(pa);
    if(!e||!MmIsAddressValid(e)||!e->Valid)return 0xC0000001;
    *p=((ULONG64)e->PageFrameNumber<<12)|(v&0xFFFULL);*l=FALSE;return 0;}
NTSTATUS GhostReadWrite(SPFN_CTX* ctx,ULONG64 cr3,ULONG64 v,PVOID b,SIZE_T s,BOOLEAN w){
    SIZE_T rM=s,dN=0;
    while(rM>0){
        ULONG64 pO=v&0xFFF,cK=min(rM,4096-pO),p=0;BOOLEAN l=FALSE;
        if(!NT_SUCCESS(WalkPageTable(ctx,cr3,v,&p,&l)))return 0xC0000001;
        PHYSICAL_ADDRESS pAddr;pAddr.QuadPart=(LONGLONG)(p+pO);
        PVOID m=MmGetVirtualForPhysical(pAddr);
        /* CRITICAL: validate mapping before any memory access */
        if(!m||!MmIsAddressValid(m))return 0xC0000005;
        __try{
            if(w)RtlCopyMemory((PUCHAR)m,(PUCHAR)b+dN,cK);
            else RtlCopyMemory((PUCHAR)b+dN,(PUCHAR)m,cK);
        }__except(1){return GetExceptionCode();}
        dN+=cK;v+=cK;rM-=cK;
    }return 0;}
NTSTATUS GetProcessCr3(SPFN_CTX* ctx,HANDLE pid,ULONG64* c3){PEPROCESS p;if(!NT_SUCCESS(PsLookupProcessByProcessId(pid,&p)))return 0xC0000001;*c3=*(ULONG64*)((PUCHAR)p+ctx->DirectoryTableBaseOffset);ObDereferenceObject(p);return 0;}
NTSTATUS ReadProcessMemoryByCr3(SPFN_CTX* ctx,ULONG64 c3,ULONG64 a,PVOID b,SIZE_T s){return GhostReadWrite(ctx,c3,a,b,s,FALSE);}
NTSTATUS WriteProcessMemoryByCr3(SPFN_CTX* ctx,ULONG64 c3,ULONG64 a,PVOID b,SIZE_T s){return GhostReadWrite(ctx,c3,a,b,s,TRUE);}
NTSTATUS GetModuleBaseByPid(SPFN_CTX* ctx,HANDLE pid,PCWSTR mN,ULONG64* b){
    PEPROCESS p;if(!NT_SUCCESS(PsLookupProcessByProcessId(pid,&p)))return 0xC0000001;
    /* BUG FIX: PebOffset may be 0 if DetectProcessOffsets failed and was not caught.
     * Reading from EPROCESS+0 gives DirectoryTableBase (CR3), not the PEB pointer.
     * Apply same sanity guard used in HideProcess. */
    if(ctx->PebOffset < 0x200 || ctx->PebOffset > 0x800){
        ObDereferenceObject(p);
        return STATUS_NOT_SUPPORTED;
    }
    ULONG64 c3=*(ULONG64*)((PUCHAR)p+ctx->DirectoryTableBaseOffset),pb=*(ULONG64*)((PUCHAR)p+ctx->PebOffset);
    ObDereferenceObject(p);
    if(!pb)return 0xC0000001;
    ULONG64 ld=0,lh=0;
    if(!NT_SUCCESS(ReadProcessMemoryByCr3(ctx,c3,pb+0x18,&ld,8))||!ld)return 0xC0000001;
    if(!NT_SUCCESS(ReadProcessMemoryByCr3(ctx,c3,ld+0x20,&lh,8))||!lh)return 0xC0000001;
    ULONG64 c=lh;
    const ULONG MAX_MODULES=1024;
    ULONG iter=0;
    do{
        ULONG64 bS=0,cNext=0;
        if(!NT_SUCCESS(ReadProcessMemoryByCr3(ctx,c3,c,&cNext,8))||!cNext)break;
        ReadProcessMemoryByCr3(ctx,c3,c+0x30,&bS,8);
        UNICODE_STRING n={0};
        ReadProcessMemoryByCr3(ctx,c3,c+0x58,&n,sizeof(n));
        if(n.Length&&n.Length<=512&&n.Buffer){
            WCHAR* nb=(WCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx,n.Length+sizeof(WCHAR),'tSmM'); /* ntoskrnl MmSt tag */
            if(nb){
                RtlZeroMemory(nb,n.Length+sizeof(WCHAR));
                /* n.Buffer is a VA in the target process — pass it as ULONG64 address, not pointer */
                ULONG64 bufVA=(ULONG64)(ULONG_PTR)n.Buffer;
                if(bufVA>0x10000&&bufVA<0x7FFFFFFFFFFF){ /* basic userland VA sanity */
                    ReadProcessMemoryByCr3(ctx,c3,bufVA,nb,n.Length);
                    UNICODE_STRING us={n.Length,n.Length,nb},ut;
                    RtlInitUnicodeString(&ut,mN);
                    if(RtlCompareUnicodeString(&us,&ut,TRUE)==0){*b=bS;ExFreePool(nb);return 0;}
                }
                ExFreePool(nb);
            }
        }
        c=cNext;
    }while(c!=lh&&++iter<MAX_MODULES);
    return 0xC0000225;
}
