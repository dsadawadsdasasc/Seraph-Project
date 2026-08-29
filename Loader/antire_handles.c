/* antire_handles.c — implementação do handle-driven watcher (P6.2).
 *
 * Algoritmo por iteração:
 *   1. NtQuerySystemInformation(SystemExtendedHandleInformation, ...) — lista
 *      todos os handles do sistema (~10-50k entradas, ~MB de buffer).
 *   2. Filtro rápido em cada entrada:
 *        - OwnerPid == our_pid → skip (somos nós).
 *        - GrantedAccess sem nenhum bit perigoso → skip.
 *        - ObjectTypeIndex != Process → skip (filtramos por handle de processo
 *          apenas, ignora File/Section/etc).
 *   3. Para suspeitos remanescentes, abre handle do owner (NtOpenProcess
 *      DUP_HANDLE), duplica o handle suspeito p/ nós (SysNtDuplicateObject),
 *      consulta NtQueryInformationProcess(ProcessBasicInformation) para
 *      descobrir o TargetPid.
 *   4. Se TargetPid == our_pid OR TargetPid == d2_pid:
 *        - Lookup nome do owner via cache (re-construído quando ttl expira).
 *        - Match contra blocklists (tier-1 / tier-2 / unknown).
 *        - Tier-1 → KeyAuth_Ban + ExitProcess.
 *        - Tier-2 → log + 30s grace; se persistir, ban.
 *
 * NOTA: ObjectTypeIndex de "Process" varia entre Win10 builds.  Em vez de
 * hard-code, descobrimos uma vez por sessão chamando NtQueryObject sobre
 * GetCurrentProcess() (handle pseudo-real é o que a syscall enxerga, mas
 * para o índice de tipo basta abrir handle real para nós mesmos).
 */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_VERBOSE
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "antire_handles.h"
#include "syscalls.h"
#include "keyauth.h"
#include "debug.h"
#include "seraph_ptr_crypt.h"
#include "seraph_secure_val.h"
#include <winternl.h>
#include <string.h>
#include <wchar.h>

/* ── AH_KEY: chave base para XOR das listas (distinta de ARE_KEY em antire.c) */
#define AH_KEY 0xC3

/* Decodifica array XOR'd com chave rotativa c[i] ^= (AH_KEY + i) */
static wchar_t* _ahDec(const wchar_t* enc, int n, wchar_t* out) {
    for (int i = 0; i < n; i++)
        out[i] = enc[i] ^ (wchar_t)((unsigned char)(AH_KEY + i));
    out[n] = 0;
    return out;
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define SystemExtendedHandleInformation 0x40
#define ProcessBasicInformation         0x00

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR  NumberOfHandles;
    ULONG_PTR  Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _PROCESS_BASIC_INFORMATION_X {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;     /* o que queremos */
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_X;

#define DANGEROUS_ACCESS_MASK \
    (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
     PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)

/* === Estado da thread =================================================== */
static volatile LONG s_running    = 0;
static UINT64        s_thread_enc = 0;
static SecureVal96   s_ourPid_sec;
static SecureVal96   s_d2Pid_sec;

/* Index do tipo "Process" (descoberto runtime). */
static SecureVal96   s_processTypeIdx_sec;

/* P6.3: callback opcional para hot-revert antes de ban+exit. */
static volatile AntiRE_HotRevertFn s_hotRevert = NULL;

/* === Whitelist / Tier lists (XOR-encoded, never plaintext in .rdata) ====
 * Gerado com: for(i=0;i<len;i++) enc[i]=plain[i]^(AH_KEY+i);
 * AH_KEY = 0xC3 */

/* helper struct */
typedef struct { const wchar_t* enc; int len; } AH_ENTRY;

/* Whitelist — processos legítimos que podem ter handles abertos */
/* "explorer.exe" (12) */
static const wchar_t _w_explorer[]   = {'e'^0xC3,'x'^0xC4,'p'^0xC5,'l'^0xC6,'o'^0xC7,'r'^0xC8,'e'^0xC9,'r'^0xCA,'.'^0xCB,'e'^0xCC,'x'^0xCD,'e'^0xCE};
/* "csrss.exe" (9) */
static const wchar_t _w_csrss[]      = {'c'^0xC3,'s'^0xC4,'r'^0xC5,'s'^0xC6,'s'^0xC7,'.'^0xC8,'e'^0xC9,'x'^0xCA,'e'^0xCB};
/* "svchost.exe" (11) */
static const wchar_t _w_svchost[]    = {'s'^0xC3,'v'^0xC4,'c'^0xC5,'h'^0xC6,'o'^0xC7,'s'^0xC8,'t'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "wininit.exe" (11) */
static const wchar_t _w_wininit[]    = {'w'^0xC3,'i'^0xC4,'n'^0xC5,'i'^0xC6,'n'^0xC7,'i'^0xC8,'t'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "lsass.exe" (9) */
static const wchar_t _w_lsass[]      = {'l'^0xC3,'s'^0xC4,'a'^0xC5,'s'^0xC6,'s'^0xC7,'.'^0xC8,'e'^0xC9,'x'^0xCA,'e'^0xCB};
/* "dwm.exe" (7) */
static const wchar_t _w_dwm[]        = {'d'^0xC3,'w'^0xC4,'m'^0xC5,'.'^0xC6,'e'^0xC7,'x'^0xC8,'e'^0xC9};
/* "runtimebroker.exe" (18) */
static const wchar_t _w_rtbroker[]   = {'r'^0xC3,'u'^0xC4,'n'^0xC5,'t'^0xC6,'i'^0xC7,'m'^0xC8,'e'^0xC9,'b'^0xCA,'r'^0xCB,'o'^0xCC,'k'^0xCD,'e'^0xCE,'r'^0xCF,'.'^0xD0,'e'^0xD1,'x'^0xD2,'e'^0xD3};
/* "audiodg.exe" (11) */
static const wchar_t _w_audiodg[]    = {'a'^0xC3,'u'^0xC4,'d'^0xC5,'i'^0xC6,'o'^0xC7,'d'^0xC8,'g'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "fontdrvhost.exe" (15) */
static const wchar_t _w_fontdrv[]    = {'f'^0xC3,'o'^0xC4,'n'^0xC5,'t'^0xC6,'d'^0xC7,'r'^0xC8,'v'^0xC9,'h'^0xCA,'o'^0xCB,'s'^0xCC,'t'^0xCD,'.'^0xCE,'e'^0xCF,'x'^0xD0,'e'^0xD1};
/* "dllhost.exe" (11) */
static const wchar_t _w_dllhost[]    = {'d'^0xC3,'l'^0xC4,'l'^0xC5,'h'^0xC6,'o'^0xC7,'s'^0xC8,'t'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "conhost.exe" (11) */
static const wchar_t _w_conhost[]    = {'c'^0xC3,'o'^0xC4,'n'^0xC5,'h'^0xC6,'o'^0xC7,'s'^0xC8,'t'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "nvcontainer.exe" (16) */
static const wchar_t _w_nvcont[]     = {'n'^0xC3,'v'^0xC4,'c'^0xC5,'o'^0xC6,'n'^0xC7,'t'^0xC8,'a'^0xC9,'i'^0xCA,'n'^0xCB,'e'^0xCC,'r'^0xCD,'.'^0xCE,'e'^0xCF,'x'^0xD0,'e'^0xD1};
/* "steam.exe" (9) */
static const wchar_t _w_steam[]      = {'s'^0xC3,'t'^0xC4,'e'^0xC5,'a'^0xC6,'m'^0xC7,'.'^0xC8,'e'^0xC9,'x'^0xCA,'e'^0xCB};
/* "battleye.exe" (12) */
static const wchar_t _w_battleye[]   = {'b'^0xC3,'a'^0xC4,'t'^0xC5,'t'^0xC6,'l'^0xC7,'e'^0xC8,'y'^0xC9,'e'^0xCA,'.'^0xCB,'e'^0xCC,'x'^0xCD,'e'^0xCE};
/* "beservice.exe" (13) */
static const wchar_t _w_beservice[]  = {'b'^0xC3,'e'^0xC4,'s'^0xC5,'e'^0xC6,'r'^0xC7,'v'^0xC8,'i'^0xC9,'c'^0xCA,'e'^0xCB,'.'^0xCC,'e'^0xCD,'x'^0xCE,'e'^0xCF};
/* "msmpeng.exe" (11) */
static const wchar_t _w_msmpeng[]    = {'m'^0xC3,'s'^0xC4,'m'^0xC5,'p'^0xC6,'e'^0xC7,'n'^0xC8,'g'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "avp.exe" (7) */
static const wchar_t _w_avp[]        = {'a'^0xC3,'v'^0xC4,'p'^0xC5,'.'^0xC6,'e'^0xC7,'x'^0xC8,'e'^0xC9};
/* "mbamservice.exe" (15) */
static const wchar_t _w_mbam[]       = {'m'^0xC3,'b'^0xC4,'a'^0xC5,'m'^0xC6,'s'^0xC7,'e'^0xC8,'r'^0xC9,'v'^0xCA,'i'^0xCB,'c'^0xCC,'e'^0xCD,'.'^0xCE,'e'^0xCF,'x'^0xD0,'e'^0xD1};
/* "xboxgameoverlayui.exe" (21) */
static const wchar_t _w_xbox[]       = {'x'^0xC3,'b'^0xC4,'o'^0xC5,'x'^0xC6,'g'^0xC7,'a'^0xC8,'m'^0xC9,'e'^0xCA,'o'^0xCB,'v'^0xCC,'e'^0xCD,'r'^0xCE,'l'^0xCF,'a'^0xD0,'y'^0xD1,'u'^0xD2,'i'^0xD3,'.'^0xD4,'e'^0xD5,'x'^0xD6,'e'^0xD7};

static const AH_ENTRY k_whitelist[] = {
    {_w_explorer,12},{_w_csrss,9},{_w_svchost,11},{_w_wininit,11},
    {_w_lsass,9},{_w_dwm,7},{_w_rtbroker,17},{_w_audiodg,11},
    {_w_fontdrv,15},{_w_dllhost,11},{_w_conhost,11},
    {_w_nvcont,15},{_w_steam,9},{_w_battleye,12},{_w_beservice,13},
    {_w_msmpeng,11},{_w_avp,7},{_w_mbam,15},{_w_xbox,21},
    {NULL,0}
};

/* Tier-1: ban imediato */
/* "x64dbg.exe" (10) */
static const wchar_t _t1_x64dbg[]   = {'x'^0xC3,'6'^0xC4,'4'^0xC5,'d'^0xC6,'b'^0xC7,'g'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB,'e'^0xCC};
/* "x32dbg.exe" (10) */
static const wchar_t _t1_x32dbg[]   = {'x'^0xC3,'3'^0xC4,'2'^0xC5,'d'^0xC6,'b'^0xC7,'g'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB,'e'^0xCC};
/* "windbg.exe" (9) */
static const wchar_t _t1_windbg[]   = {'w'^0xC3,'i'^0xC4,'n'^0xC5,'d'^0xC6,'b'^0xC7,'g'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB}; /* note: prefix match is ok */
/* "ollydbg.exe" (11) */
static const wchar_t _t1_olly[]     = {'o'^0xC3,'l'^0xC4,'l'^0xC5,'y'^0xC6,'d'^0xC7,'b'^0xC8,'g'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "ida.exe" (7) */
static const wchar_t _t1_ida[]      = {'i'^0xC3,'d'^0xC4,'a'^0xC5,'.'^0xC6,'e'^0xC7,'x'^0xC8,'e'^0xC9};
/* "ida64.exe" (9) */
static const wchar_t _t1_ida64[]    = {'i'^0xC3,'d'^0xC4,'a'^0xC5,'6'^0xC6,'4'^0xC7,'.'^0xC8,'e'^0xC9,'x'^0xCA,'e'^0xCB};
/* "radare2.exe" (11) */
static const wchar_t _t1_radare2[]  = {'r'^0xC3,'a'^0xC4,'d'^0xC5,'a'^0xC6,'r'^0xC7,'e'^0xC8,'2'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "binaryninja.exe" (16) */
static const wchar_t _t1_binja[]    = {'b'^0xC3,'i'^0xC4,'n'^0xC5,'a'^0xC6,'r'^0xC7,'y'^0xC8,'n'^0xC9,'i'^0xCA,'n'^0xCB,'j'^0xCC,'a'^0xCD,'.'^0xCE,'e'^0xCF,'x'^0xD0,'e'^0xD1};
/* "cutter.exe" (10) */
static const wchar_t _t1_cutter[]   = {'c'^0xC3,'u'^0xC4,'t'^0xC5,'t'^0xC6,'e'^0xC7,'r'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB,'e'^0xCC};
/* "dnspy.exe" (9) */
static const wchar_t _t1_dnspy[]    = {'d'^0xC3,'n'^0xC4,'s'^0xC5,'p'^0xC6,'y'^0xC7,'.'^0xC8,'e'^0xC9,'x'^0xCA,'e'^0xCB};
/* "reclass.exe" (11) */
static const wchar_t _t1_reclass[]  = {'r'^0xC3,'e'^0xC4,'c'^0xC5,'l'^0xC6,'a'^0xC7,'s'^0xC8,'s'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "scylla.exe" (10) */
static const wchar_t _t1_scylla[]   = {'s'^0xC3,'c'^0xC4,'y'^0xC5,'l'^0xC6,'l'^0xC7,'a'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB,'e'^0xCC};
/* "procdump.exe" (12) */
static const wchar_t _t1_procdump[] = {'p'^0xC3,'r'^0xC4,'o'^0xC5,'c'^0xC6,'d'^0xC7,'u'^0xC8,'m'^0xC9,'p'^0xCA,'.'^0xCB,'e'^0xCC,'x'^0xCD,'e'^0xCE};
/* "cheatengine" (11 — prefix) */
static const wchar_t _t1_ce[]       = {'c'^0xC3,'h'^0xC4,'e'^0xC5,'a'^0xC6,'t'^0xC7,'e'^0xC8,'n'^0xC9,'g'^0xCA,'i'^0xCB,'n'^0xCC,'e'^0xCD};
/* "ceserver.exe" (12) */
static const wchar_t _t1_ceserver[] = {'c'^0xC3,'e'^0xC4,'s'^0xC5,'e'^0xC6,'r'^0xC7,'v'^0xC8,'e'^0xC9,'r'^0xCA,'.'^0xCB,'e'^0xCC,'x'^0xCD,'e'^0xCE};
/* "hxd.exe" (7) */
static const wchar_t _t1_hxd[]      = {'h'^0xC3,'x'^0xC4,'d'^0xC5,'.'^0xC6,'e'^0xC7,'x'^0xC8,'e'^0xC9};
/* "ghidra.exe" (10) */
static const wchar_t _t1_ghidra[]   = {'g'^0xC3,'h'^0xC4,'i'^0xC5,'d'^0xC6,'r'^0xC7,'a'^0xC8,'.'^0xC9,'e'^0xCA,'x'^0xCB,'e'^0xCC};
/* "pe-sieve.exe" (12) */
static const wchar_t _t1_pesieve[]  = {'p'^0xC3,'e'^0xC4,'-'^0xC5,'s'^0xC6,'i'^0xC7,'e'^0xC8,'v'^0xC9,'e'^0xCA,'.'^0xCB,'e'^0xCC,'x'^0xCD,'e'^0xCE};

static const AH_ENTRY k_tier1[] = {
    {_t1_x64dbg,10},{_t1_x32dbg,10},{_t1_windbg,9},{_t1_olly,11},
    {_t1_ida,7},{_t1_ida64,9},{_t1_radare2,11},{_t1_binja,15},
    {_t1_cutter,10},{_t1_dnspy,9},{_t1_reclass,11},{_t1_scylla,10},
    {_t1_procdump,12},{_t1_ce,11},{_t1_ceserver,12},{_t1_hxd,7},
    {_t1_ghidra,10},{_t1_pesieve,12},
    {NULL,0}
};

/* Tier-2: monitor — log + grace */
/* "processhacker.exe" (18) */
static const wchar_t _t2_phacker[]  = {'p'^0xC3,'r'^0xC4,'o'^0xC5,'c'^0xC6,'e'^0xC7,'s'^0xC8,'s'^0xC9,'h'^0xCA,'a'^0xCB,'c'^0xCC,'k'^0xCD,'e'^0xCE,'r'^0xCF,'.'^0xD0,'e'^0xD1,'x'^0xD2,'e'^0xD3};
/* "systeminformer.exe" (19) */
static const wchar_t _t2_sysinf[]   = {'s'^0xC3,'y'^0xC4,'s'^0xC5,'t'^0xC6,'e'^0xC7,'m'^0xC8,'i'^0xC9,'n'^0xCA,'f'^0xCB,'o'^0xCC,'r'^0xCD,'m'^0xCE,'e'^0xCF,'r'^0xD0,'.'^0xD1,'e'^0xD2,'x'^0xD3,'e'^0xD4};
/* "procexp.exe" (11) */
static const wchar_t _t2_procexp[]  = {'p'^0xC3,'r'^0xC4,'o'^0xC5,'c'^0xC6,'e'^0xC7,'x'^0xC8,'p'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "wireshark.exe" (13) */
static const wchar_t _t2_wireshark[]= {'w'^0xC3,'i'^0xC4,'r'^0xC5,'e'^0xC6,'s'^0xC7,'h'^0xC8,'a'^0xC9,'r'^0xCA,'k'^0xCB,'.'^0xCC,'e'^0xCD,'x'^0xCE,'e'^0xCF};
/* "procmon.exe" (11) */
static const wchar_t _t2_procmon[]  = {'p'^0xC3,'r'^0xC4,'o'^0xC5,'c'^0xC6,'m'^0xC7,'o'^0xC8,'n'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "fiddler.exe" (11) */
static const wchar_t _t2_fiddler[]  = {'f'^0xC3,'i'^0xC4,'d'^0xC5,'d'^0xC6,'l'^0xC7,'e'^0xC8,'r'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};
/* "apimonitor.exe" (14) */
static const wchar_t _t2_apimon[]   = {'a'^0xC3,'p'^0xC4,'i'^0xC5,'m'^0xC6,'o'^0xC7,'n'^0xC8,'i'^0xC9,'t'^0xCA,'o'^0xCB,'r'^0xCC,'.'^0xCD,'e'^0xCE,'x'^0xCF,'e'^0xD0};
/* "mitmproxy.exe" (13) */
static const wchar_t _t2_mitm[]     = {'m'^0xC3,'i'^0xC4,'t'^0xC5,'m'^0xC6,'p'^0xC7,'r'^0xC8,'o'^0xC9,'x'^0xCA,'y'^0xCB,'.'^0xCC,'e'^0xCD,'x'^0xCE,'e'^0xCF};
/* "dbgview.exe" (11) */
static const wchar_t _t2_dbgview[]  = {'d'^0xC3,'b'^0xC4,'g'^0xC5,'v'^0xC6,'i'^0xC7,'e'^0xC8,'w'^0xC9,'.'^0xCA,'e'^0xCB,'x'^0xCC,'e'^0xCD};

static const AH_ENTRY k_tier2[] = {
    {_t2_phacker,17},{_t2_sysinf,18},{_t2_procexp,11},{_t2_wireshark,13},
    {_t2_procmon,11},{_t2_fiddler,11},{_t2_apimon,14},{_t2_mitm,13},
    {_t2_dbgview,11},
    {NULL,0}
};

/* === Helpers ============================================================ */

/* nameInList: decodifica cada entrada no stack, compara, limpa. */
static BOOL nameInList(const wchar_t* name, const AH_ENTRY* list) {
    if (!name) return FALSE;
    wchar_t dec[48];
    for (int i = 0; list[i].enc; i++) {
        _ahDec(list[i].enc, list[i].len, dec);
        /* case-insensitive manual compare (sem _wcsicmp CRT) */
        BOOL match = TRUE;
        const wchar_t* a = name; const wchar_t* b = dec;
        while (*a && *b) {
            wchar_t ca = *a, cb = *b;
            if (ca>='A'&&ca<='Z') ca+=32;
            if (cb>='A'&&cb<='Z') cb+=32;
            if (ca!=cb){match=FALSE;break;}
            a++;b++;
        }
        if (match && !*b) { SecureZeroMemory(dec,sizeof(dec)); return TRUE; }
        SecureZeroMemory(dec,sizeof(dec));
    }
    return FALSE;
}

/* Cache de nomes de processo dono (amortiza o custo da syscall por 30s) */
typedef struct {
    DWORD   pid;
    wchar_t name[64];
    DWORD   ttl;
} OwnerCacheEntry;

#define OWNER_CACHE_SIZE 64
static OwnerCacheEntry s_ownerCache[OWNER_CACHE_SIZE];

/* lookupOwnerName: resolve nome do processo owner via SysNtQuerySystemInformation.
 * Cache com TTL de 30s para amortizar custo. Sem CreateToolhelp32Snapshot. */
static const wchar_t* lookupOwnerName(DWORD pid) {
    DWORD now = GetTickCount();
    /* Cache hit */
    for (int i = 0; i < OWNER_CACHE_SIZE; i++) {
        if (s_ownerCache[i].pid == pid && (now - s_ownerCache[i].ttl) < 30000)
            return s_ownerCache[i].name;
    }
    /* Resolve via direct syscall */
    ULONG sz = 0x20000;
    BYTE *buf = NULL;
    NTSTATUS st;
    for (int tries = 0; tries < 6; tries++) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!buf) return NULL;
        ULONG ret = 0;
        st = SysNtQuerySystemInformation(5, buf, sz, &ret);
        if (NT_SUCCESS(st)) break;
        if ((ULONG)st == 0xC0000004) { sz = ret + 0x4000; continue; }
        HeapFree(GetProcessHeap(), 0, buf); return NULL;
    }
    if (!buf || !NT_SUCCESS(st)) { if (buf) HeapFree(GetProcessHeap(), 0, buf); return NULL; }

    const wchar_t *result = NULL;
    BYTE *p = buf;
    for (;;) {
        ULONG   next    = *(ULONG*)(p);
        ULONG_PTR spid  = *(ULONG_PTR*)(p + 0x50);
        USHORT  nameLen = *(USHORT*)(p + 0x38);
        PWSTR   namePtr = *(PWSTR* )(p + 0x40);
        if ((DWORD)spid == pid && namePtr && nameLen > 0 && nameLen <= 256) {
            int nChars = nameLen / 2;
            if (nChars > 63) nChars = 63;
            /* Insere/atualiza cache */
            int oldest = 0; DWORD oldestT = 0xFFFFFFFFu;
            for (int i = 0; i < OWNER_CACHE_SIZE; i++) {
                if (s_ownerCache[i].pid == 0 || s_ownerCache[i].ttl < oldestT) {
                    oldest = i; oldestT = s_ownerCache[i].ttl;
                }
            }
            s_ownerCache[oldest].pid = pid;
            s_ownerCache[oldest].ttl = now;
            for (int c = 0; c < nChars; c++) s_ownerCache[oldest].name[c] = namePtr[c];
            s_ownerCache[oldest].name[nChars] = 0;
            result = s_ownerCache[oldest].name;
            break;
        }
        if (next == 0) break;
        p += next;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

/* === Action: ban + exit ================================================= */
static void actBanAndExit(const wchar_t* reason, DWORD ownerPid) {
    WLFF("ah: BAN pid=%lu", ownerPid);
    (void)reason;
#ifdef NDEBUG
    /* P6.3 — hot-revert: apaga patches em D2 antes do exit, removendo
     * evidência forense do `.text` modificado. */
    AntiRE_HotRevertFn rev = (AntiRE_HotRevertFn)
        InterlockedCompareExchangePointer((void* volatile*)&s_hotRevert, NULL, NULL);
    if (rev) rev();
    KeyAuth_BanCurrentKey();
    SeraphSleep(500);
    ExitProcess(0);   /* P5: exit code neutro — 0xDEADBEEF era assinável */
#else
    /* DEBUG: só loga */
#endif
}

void AntiRE_Handles_SetHotRevert(AntiRE_HotRevertFn fn) {
    InterlockedExchangePointer((void* volatile*)&s_hotRevert, (void*)fn);
}

/* resolve_d2_pid_lazy: resolve PID do destiny2.exe via syscall direta.
 * Sem CreateToolhelp32Snapshot — invisível a callbacks de kernel. */
static DWORD resolve_d2_pid_lazy(void) {
    /* "destiny2.exe" XOR'd com chave 0x4B (igual a evasion_user.c) */
    char _d2[14];
    { static const char _e[]={0x2F,0x2E,0x38,0x3F,0x22,0x25,0x32,0x79,0x65,0x2E,0x33,0x2E,0x00};
      for(int i=0;i<12;i++) _d2[i]=_e[i]^0x4B; _d2[12]=0; }
    wchar_t _d2w[14];
    for(int i=0;i<13;i++) _d2w[i]=(wchar_t)(unsigned char)_d2[i];
    _d2w[12]=0;

    ULONG sz = 0x20000;
    BYTE *buf = NULL;
    NTSTATUS st;
    DWORD found = 0;
    for (int tries = 0; tries < 6; tries++) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!buf) goto _r_cleanup;
        ULONG ret = 0;
        st = SysNtQuerySystemInformation(5, buf, sz, &ret);
        if (NT_SUCCESS(st)) break;
        if ((ULONG)st == 0xC0000004) { sz = ret + 0x4000; continue; }
        HeapFree(GetProcessHeap(), 0, buf); buf = NULL; goto _r_cleanup;
    }
    if (!buf || !NT_SUCCESS(st)) goto _r_cleanup;

    { BYTE *p = buf;
      for (;;) {
        ULONG   next    = *(ULONG*)(p);
        ULONG_PTR spid  = *(ULONG_PTR*)(p + 0x50);
        USHORT  nameLen = *(USHORT*)(p + 0x38);
        PWSTR   namePtr = *(PWSTR* )(p + 0x40);
        if (namePtr && nameLen > 0 && nameLen <= 24) { /* max "destiny2.exe"=26 bytes */
            int nChars = nameLen / 2;
            BOOL eq = TRUE; int k = 0;
            while (k < nChars && _d2w[k]) {
                wchar_t ca = namePtr[k], cb = _d2w[k];
                if (ca>='A'&&ca<='Z') ca+=32;
                if (cb>='A'&&cb<='Z') cb+=32;
                if (ca!=cb){eq=FALSE;break;} k++;
            }
            if (eq && k == nChars && !_d2w[k]) { found = (DWORD)spid; break; }
        }
        if (next == 0) break;
        p += next;
      }
    }

_r_cleanup:
    SecureZeroMemory(_d2, sizeof(_d2)); SecureZeroMemory(_d2w, sizeof(_d2w));
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    return found;
}

/* === Core scan ========================================================== */
static void scan_once(void) {
    DWORD ourPid = (DWORD)SecureRead(&s_ourPid_sec);
    DWORD d2Pid  = (DWORD)SecureRead(&s_d2Pid_sec);
    if (d2Pid == 0) {
        d2Pid = resolve_d2_pid_lazy();
        if (d2Pid) SecureWrite(&s_d2Pid_sec, d2Pid);
    }

    /* Buffer crescente para SystemExtendedHandleInformation. */
    ULONG sz = 0x80000;
    BYTE* buf = NULL;
    NTSTATUS st;
    for (int tries = 0; tries < 6; tries++) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!buf) return;
        ULONG ret = 0;
        st = SysNtQuerySystemInformation(SystemExtendedHandleInformation,
                                          buf, sz, &ret);
        if (NT_SUCCESS(st)) break;
        if (st == (NTSTATUS)0xC0000004 /* INFO_LENGTH_MISMATCH */) {
            sz *= 2; continue;
        }
        HeapFree(GetProcessHeap(), 0, buf); buf = NULL;
        return;
    }
    if (!buf) return;

    SYSTEM_HANDLE_INFORMATION_EX* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* h = info->Handles;

    HANDLE hOurProc = GetCurrentProcess();

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        DWORD ownerPid = (DWORD)h[i].UniqueProcessId;
        if (ownerPid == ourPid || ownerPid == 0 || ownerPid == 4) continue;
        if ((h[i].GrantedAccess & DANGEROUS_ACCESS_MASK) == 0) continue;
        /* Filtro por type: ignoramos se não conseguimos descobrir; aceita
         * qualquer index — o NtDuplicate falhará gracefully se não for Process. */

        /* Abre handle do owner com DUP_HANDLE para poder duplicar. */
        HANDLE hOwner = NULL;
        OBJECT_ATTRIBUTES oa = {0}; oa.Length = sizeof(oa);
        CLIENT_ID cid = {0}; cid.UniqueProcess = (HANDLE)(ULONG_PTR)ownerPid;
        st = SysNtOpenProcess(&hOwner, PROCESS_DUP_HANDLE, &oa, &cid);
        if (!NT_SUCCESS(st) || !hOwner) continue;

        HANDLE hDup = NULL;
        st = SysNtDuplicateObject(hOwner, (HANDLE)h[i].HandleValue,
                                  hOurProc, &hDup,
                                  PROCESS_QUERY_LIMITED_INFORMATION,
                                  0, 0);
        SysNtClose(hOwner);
        if (!NT_SUCCESS(st) || !hDup) continue;

        PROCESS_BASIC_INFORMATION_X pbi = {0};
        ULONG retLen = 0;
        st = SysNtQueryInformationProcess(hDup, ProcessBasicInformation,
                                          &pbi, sizeof(pbi), &retLen);
        SysNtClose(hDup);
        if (!NT_SUCCESS(st)) continue;

        DWORD targetPid = (DWORD)pbi.UniqueProcessId;
        BOOL isUs   = (targetPid == ourPid);
        BOOL isD2   = (d2Pid != 0 && targetPid == d2Pid);
        if (!isUs && !isD2) continue;

        /* Owner tem handle pra nós ou pro D2 — investigar nome. */
        const wchar_t* ownerName = lookupOwnerName(ownerPid);
        if (!ownerName) continue;

        if (nameInList(ownerName, k_whitelist)) continue;

        if (nameInList(ownerName, k_tier1)) {
            actBanAndExit(ownerName, ownerPid);
            HeapFree(GetProcessHeap(), 0, buf);
            return;
        }
        if (nameInList(ownerName, k_tier2)) {
            WLFF("ah: t2 pid=%lu acc=0x%X", ownerPid, h[i].GrantedAccess);
            /* TODO: grace 30s + reverify; por ora só loga */
            continue;
        }

        WLFF("ah: unk pid=%lu acc=0x%X", ownerPid, h[i].GrantedAccess);
    }

    HeapFree(GetProcessHeap(), 0, buf);
}

/* === Thread loop ======================================================== */
static DWORD WINAPI watcher_thread(LPVOID p) {
    (void)p;
    while (InterlockedCompareExchange(&s_running, 0, 0)) {
        scan_once();
        /* P10: intervalo aleatorizado 1800-3400ms — padrão fixo de 2s é assinável */
        DWORD _dt = 1800 + (DWORD)((GetTickCount() ^ (GetTickCount()>>7)) % 1600);
        SeraphSleep(_dt);
    }
    return 0;
}

/* discover_process_type_idx: descobre o ObjectTypeIndex de handles do tipo
 * "Process" abrindo um handle real para o pr�prio processo e vasculhando
 * SystemExtendedHandleInformation para encontrar a entrada correspondente.
 * Fallback: 7 (Win10 typical) ou 8 (Win11 typical) se scan falhar. */
static void discover_process_type_idx(DWORD ourPid) {
    /* Abre handle real (nao pseudo-handle) para nos mesmos */
    HANDLE hSelf = NULL;
    OBJECT_ATTRIBUTES oa = {0}; oa.Length = sizeof(oa);
    CLIENT_ID cid = {0}; cid.UniqueProcess = (HANDLE)(ULONG_PTR)ourPid;
    NTSTATUS st = SysNtOpenProcess(&hSelf, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(st) || !hSelf) {
        /* Fallback: win10=7, win11=8 — tenta ambos inspecionando versao */
        OSVERSIONINFOEXW ov = {0}; ov.dwOSVersionInfoSize = sizeof(ov);
        SecureWrite(&s_processTypeIdx_sec, 7); /* default Win10 */
        WLF("ah: NtOp-self fail, idx=7");
        return;
    }

    /* Tenta encontrar nosso handle na tabela para extrair TypeIndex */
    ULONG sz = 0x80000;
    BYTE *buf = NULL;
    USHORT foundIdx = 0;
    for (int tries = 0; tries < 6; tries++) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
        if (!buf) break;
        ULONG ret = 0;
        st = SysNtQuerySystemInformation(SystemExtendedHandleInformation, buf, sz, &ret);
        if (NT_SUCCESS(st)) break;
        if ((ULONG)st == 0xC0000004) { sz = ret + 0x8000; continue; }
        HeapFree(GetProcessHeap(), 0, buf); buf = NULL; break;
    }

    if (buf && NT_SUCCESS(st)) {
        SYSTEM_HANDLE_INFORMATION_EX *info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
        for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
            if ((DWORD)e->UniqueProcessId == ourPid &&
                (ULONG_PTR)e->HandleValue == (ULONG_PTR)hSelf) {
                foundIdx = e->ObjectTypeIndex;
                break;
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }
    SysNtClose(hSelf);

    if (foundIdx > 0) {
        SecureWrite(&s_processTypeIdx_sec, foundIdx);
        WLFF("ah: TypeIdx=%u", foundIdx);
    } else {
        /* Fallback heuristico: Win10=7, Win11=8 */
        SecureWrite(&s_processTypeIdx_sec, 7);
        WLF("ah: TypeIdx disc fail, fallback=7");
    }
}

void AntiRE_Handles_Start(DWORD ourPid) {
    if (InterlockedCompareExchange(&s_running, 1, 0) != 0) return;
    SecureWrite(&s_ourPid_sec, ourPid);
    /* P6: descobrir TypeIndex robusto antes de iniciar a thread */
    discover_process_type_idx(ourPid);
    HANDLE hThread = SeraphCreateThread(watcher_thread, NULL);
    s_thread_enc = (UINT64)SERAPH_ENC_PTR(hThread, &s_thread_enc);
}


void AntiRE_Handles_SetD2Pid(DWORD d2Pid) {
    SecureWrite(&s_d2Pid_sec, d2Pid);
}

void AntiRE_Handles_Stop(void) {
    InterlockedExchange(&s_running, 0);
    HANDLE hThread = (HANDLE)SERAPH_DEC_PTR(s_thread_enc, &s_thread_enc);
    if (hThread) {
        WaitForSingleObject(hThread, 3000);
        SysNtClose(hThread);
        s_thread_enc = 0;
    }
}
