/* antire.c — Anti-Reverse-Engineering monitor
 * Periodically scans for RE tools via process enumeration.
 * RELEASE: bans key + 30s delay + silent exit.
 * DEBUG:   logs only, no action. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "antire.h"
#include "keyauth.h"
#include "attach.h"
#include "debug.h"
#include "seraph_ban_marker.h"
#include "ThemidaSDK.h"
#include "xor_strings.h"   /* ENC_* arrays + XOR_KEY */
#include "syscalls.h"   /* SysNtQuerySystemInformation — direct syscall */
#include <winternl.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>

/* ── XOR-obfuscated process names ────────────────────────────────────────
 * Each name is stored as a wchar_t array XOR'd with a per-entry key.
 * Decoded on the stack at runtime, never sits in .rdata as plaintext.
 * Key rotates per character: c[i] ^= (baseKey + i)                     */

#define ARE_KEY 0xB7  /* distinct from XOR_KEY to avoid pattern reuse */

/* Helper: decode a XOR'd wchar_t array into a stack buffer.
 * Returns pointer to `out` (null-terminated). */
static wchar_t* _areDec(const wchar_t *enc, int nChars, wchar_t *out) {
    for (int i = 0; i < nChars; i++)
        out[i] = enc[i] ^ (wchar_t)((unsigned char)(ARE_KEY + i));
    out[nChars] = 0;
    return out;
}

/* ── Pre-encrypted process names ─────────────────────────────────────────
 * Generated with: for(i=0;i<len;i++) enc[i] = plain[i] ^ (0xB7+i);
 * To regenerate, use the _areEnc helper at the bottom of this file
 * (compile with ANTIRE_GEN_TABLES defined).                              */

/* ida.exe     (7 chars) */
static const wchar_t _p_ida[] = {
    'i'^0xB7, 'd'^0xB8, 'a'^0xB9, '.'^0xBA, 'e'^0xBB,
    'x'^0xBC, 'e'^0xBD
};
/* idag64.exe  (10 chars) */
static const wchar_t _p_idag64[] = {
    'i'^0xB7, 'd'^0xB8, 'a'^0xB9, 'g'^0xBA, '6'^0xBB,
    '4'^0xBC, '.'^0xBD, 'e'^0xBE, 'x'^0xBF, 'e'^0xC0
};
/* ghidra      (6 chars) */
static const wchar_t _p_ghidra[] = {
    'g'^0xB7, 'h'^0xB8, 'i'^0xB9, 'd'^0xBA, 'r'^0xBB,
    'a'^0xBC
};
/* reclass     (7 chars) */
static const wchar_t _p_reclass[] = {
    'r'^0xB7, 'e'^0xB8, 'c'^0xB9, 'l'^0xBA, 'a'^0xBB,
    's'^0xBC, 's'^0xBD
};
/* x64dbg.exe  (10 chars) */
static const wchar_t _p_x64dbg[] = {
    'x'^0xB7, '6'^0xB8, '4'^0xB9, 'd'^0xBA, 'b'^0xBB,
    'g'^0xBC, '.'^0xBD, 'e'^0xBE, 'x'^0xBF, 'e'^0xC0
};
/* x32dbg.exe  (10 chars) */
static const wchar_t _p_x32dbg[] = {
    'x'^0xB7, '3'^0xB8, '2'^0xB9, 'd'^0xBA, 'b'^0xBB,
    'g'^0xBC, '.'^0xBD, 'e'^0xBE, 'x'^0xBF, 'e'^0xC0
};
/* processhacker (13 chars) */
static const wchar_t _p_phacker[] = {
    'p'^0xB7, 'r'^0xB8, 'o'^0xB9, 'c'^0xBA, 'e'^0xBB,
    's'^0xBC, 's'^0xBD, 'h'^0xBE, 'a'^0xBF, 'c'^0xC0,
    'k'^0xC1, 'e'^0xC2, 'r'^0xC3
};
/* hxd         (3 chars) */
static const wchar_t _p_hxd[] = {
    'h'^0xB7, 'x'^0xB8, 'd'^0xB9
};
/* apimonitor  (10 chars) */
static const wchar_t _p_apimon[] = {
    'a'^0xB7, 'p'^0xB8, 'i'^0xB9, 'm'^0xBA, 'o'^0xBB,
    'n'^0xBC, 'i'^0xBD, 't'^0xBE, 'o'^0xBF, 'r'^0xC0
};
/* dnspy       (5 chars) — matches dnSpy.exe */
static const wchar_t _p_dnspy[] = {
    'd'^0xB7, 'n'^0xB8, 's'^0xB9, 'p'^0xBA, 'y'^0xBB
};
/* ollydbg     (7 chars) */
static const wchar_t _p_ollydbg[] = {
    'o'^0xB7, 'l'^0xB8, 'l'^0xB9, 'y'^0xBA, 'd'^0xBB,
    'b'^0xBC, 'g'^0xBD
};
/* windbg      (6 chars) — matches windbg.exe, windbgx.exe */
static const wchar_t _p_windbg[] = {
    'w'^0xB7, 'i'^0xB8, 'n'^0xB9, 'd'^0xBA, 'b'^0xBB,
    'g'^0xBC
};
/* immunit     (7 chars) — matches ImmunityDebugger.exe */
static const wchar_t _p_immunit[] = {
    'i'^0xB7, 'm'^0xB8, 'm'^0xB9, 'u'^0xBA, 'n'^0xBB,
    'i'^0xBC, 't'^0xBD
};
/* binaryninja (11 chars) */
static const wchar_t _p_binja[] = {
    'b'^0xB7, 'i'^0xB8, 'n'^0xB9, 'a'^0xBA, 'r'^0xBB,
    'y'^0xBC, 'n'^0xBD, 'i'^0xBE, 'n'^0xBF, 'j'^0xC0,
    'a'^0xC1
};
/* cutter      (6 chars) — Rizin/Cutter RE framework */
static const wchar_t _p_cutter[] = {
    'c'^0xB7, 'u'^0xB8, 't'^0xB9, 't'^0xBA, 'e'^0xBB,
    'r'^0xBC
};
/* detectiteasy (5 chars "die.e") — Detect It Easy (die.exe) */
static const wchar_t _p_die[] = {
    'd'^0xB7, 'i'^0xB8, 'e'^0xB9, '.'^0xBA, 'e'^0xBB
};
/* pe-bear     (7 chars) — PE-bear.exe */
static const wchar_t _p_pebear[] = {
    'p'^0xB7, 'e'^0xB8, '-'^0xB9, 'b'^0xBA, 'e'^0xBB,
    'a'^0xBC, 'r'^0xBD
};
/* cffexplor   (9 chars) — CFF Explorer */
static const wchar_t _p_cffexpl[] = {
    'c'^0xB7, 'f'^0xB8, 'f'^0xB9, 'e'^0xBA, 'x'^0xBB,
    'p'^0xBC, 'l'^0xBD, 'o'^0xBE, 'r'^0xBF
};
/* scylla      (6 chars) — Scylla import reconstructor */
static const wchar_t _p_scylla[] = {
    's'^0xB7, 'c'^0xB8, 'y'^0xB9, 'l'^0xBA, 'l'^0xBB,
    'a'^0xBC
};
/* pestudio    (8 chars) */
static const wchar_t _p_pestudio[] = {
    'p'^0xB7, 'e'^0xB8, 's'^0xB9, 't'^0xBA, 'u'^0xBB,
    'd'^0xBC, 'i'^0xBD, 'o'^0xBE
};
/* reshack     (7 chars) — Resource Hacker */
static const wchar_t _p_reshack[] = {
    'r'^0xB7, 'e'^0xB8, 's'^0xB9, 'h'^0xBA, 'a'^0xBB,
    'c'^0xBC, 'k'^0xBD
};
/* radare      (6 chars) — radare2 */
static const wchar_t _p_radare[] = {
    'r'^0xB7, 'a'^0xB8, 'd'^0xB9, 'a'^0xBA, 'r'^0xBB,
    'e'^0xBC
};
/* fiddler     (7 chars) — Fiddler HTTP debugger */
static const wchar_t _p_fiddler[] = {
    'f'^0xB7, 'i'^0xB8, 'd'^0xB9, 'd'^0xBA, 'l'^0xBB,
    'e'^0xBC, 'r'^0xBD
};

/* ksdumper (8 chars) */
static const wchar_t _p_ksdumper[] = {
    0x00DC, 0x00CB, 0x00DD, 0x00CF, 0x00D6, 0x00CC, 0x00D8, 0x00CC
};
/* megadumper (10 chars) */
static const wchar_t _p_megadumper[] = {
    0x00DA, 0x00DD, 0x00DE, 0x00DB, 0x00DF, 0x00C9, 0x00D0, 0x00CE, 0x00DA, 0x00B2
};
/* extremedumper (13 chars) */
static const wchar_t _p_extremedumper[] = {
    0x00D2, 0x00C0, 0x00CD, 0x00C8, 0x00DE, 0x00D1, 0x00D8, 0x00DA, 0x00CA, 0x00AD, 0x00B1, 0x00A7, 0x00B1
};
/* procdump (8 chars) */
static const wchar_t _p_procdump[] = {
    0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DF, 0x00C9, 0x00D0, 0x00CE
};
/* petools (7 chars) */
static const wchar_t _p_petools[] = {
    0x00C7, 0x00DD, 0x00CD, 0x00D5, 0x00D4, 0x00D0, 0x00CE
};
/* pethief (7 chars) */
static const wchar_t _p_pethief[] = {
    0x00C7, 0x00DD, 0x00CD, 0x00D2, 0x00D2, 0x00D9, 0x00DB
};
/* titanhide (9 chars) */
static const wchar_t _p_titanhide[] = {
    0x00C3, 0x00D1, 0x00CD, 0x00DB, 0x00D5, 0x00D4, 0x00D4, 0x00DA, 0x00DA
};
/* processdump (11 chars) */
static const wchar_t _p_procdump2[] = {
    0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DE, 0x00CF, 0x00CE, 0x00DA, 0x00CA, 0x00AD, 0x00B1
};
/* netdumper (9 chars) */
static const wchar_t _p_netdumper[] = {
    0x00D9, 0x00DD, 0x00CD, 0x00DE, 0x00CE, 0x00D1, 0x00CD, 0x00DB, 0x00CD
};
/* scyllahide (10 chars) */
static const wchar_t _p_scyllahide[] = {
    0x00C4, 0x00DB, 0x00C0, 0x00D6, 0x00D7, 0x00DD, 0x00D5, 0x00D7, 0x00DB, 0x00A5
};
/* kdu (3 chars) — KDU */
static const wchar_t _p_kdu[] = { 0x00DC, 0x00DC, 0x00CC };
/* kernel-mode-ram (15 chars) — kernel-mode-ram-read-write */
static const wchar_t _p_kernel_mode_ram[] = { 0x00DC, 0x00DD, 0x00CB, 0x00D4, 0x00DE, 0x00D0, 0x0090, 0x00D3, 0x00D0, 0x00A4, 0x00A4, 0x00EF, 0x00B1, 0x00A5, 0x00A8 };
/* ppldump (7 chars) — PPLdump */
static const wchar_t _p_ppldump[] = { 0x00C7, 0x00C8, 0x00D5, 0x00DE, 0x00CE, 0x00D1, 0x00CD };
/* pplblade (8 chars) — PPLBlade */
static const wchar_t _p_pplblade[] = { 0x00C7, 0x00C8, 0x00D5, 0x00D8, 0x00D7, 0x00DD, 0x00D9, 0x00DB };
/* kvc (3 chars) — KVC */
static const wchar_t _p_kvc[] = { 0x00DC, 0x00CE, 0x00DA };
/* process-memory-dumper (21 chars) — Process-Memory-Dumper */
static const wchar_t _p_process_memory_dumper[] = { 0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DE, 0x00CF, 0x00CE, 0x0093, 0x00D2, 0x00A5, 0x00AC, 0x00AD, 0x00B1, 0x00BD, 0x00E8, 0x00A2, 0x00B2, 0x00A5, 0x00B9, 0x00AF, 0x00B9 };
/* libmem (6 chars) — libmem */
static const wchar_t _p_libmem[] = { 0x00DB, 0x00D1, 0x00DB, 0x00D7, 0x00DE, 0x00D1 };
/* poggers (7 chars) — poggers */
static const wchar_t _p_poggers[] = { 0x00C7, 0x00D7, 0x00DE, 0x00DD, 0x00DE, 0x00CE, 0x00CE };
/* arymem (6 chars) — AryMem */
static const wchar_t _p_arymem[] = { 0x00D6, 0x00CA, 0x00C0, 0x00D7, 0x00DE, 0x00D1 };
/* unmapper (8 chars) — Unmapper */
static const wchar_t _p_unmapper[] = { 0x00C2, 0x00D6, 0x00D4, 0x00DB, 0x00CB, 0x00CC, 0x00D8, 0x00CC };
/* memory-mirror (13 chars) — memory-mirror */
static const wchar_t _p_memory_mirror[] = { 0x00DA, 0x00DD, 0x00D4, 0x00D5, 0x00C9, 0x00C5, 0x0090, 0x00D3, 0x00D6, 0x00B2, 0x00B3, 0x00AD, 0x00B1 };
/* sonar (5 chars) — Sonar */
static const wchar_t _p_sonar[] = { 0x00C4, 0x00D7, 0x00D7, 0x00DB, 0x00C9 };
/* fridump (7 chars) — fridump3 */
static const wchar_t _p_fridump[] = { 0x00D1, 0x00CA, 0x00D0, 0x00DE, 0x00CE, 0x00D1, 0x00CD };
/* volatility (10 chars) — Volatility3 */
static const wchar_t _p_volatility[] = { 0x00C1, 0x00D7, 0x00D5, 0x00DB, 0x00CF, 0x00D5, 0x00D1, 0x00D7, 0x00CB, 0x00B9 };
/* winpmem (7 chars) — WinPmem */
static const wchar_t _p_winpmem[] = { 0x00C0, 0x00D1, 0x00D7, 0x00CA, 0x00D6, 0x00D9, 0x00D0 };
/* dumpit (6 chars) — DumpIt */
static const wchar_t _p_dumpit[] = { 0x00D3, 0x00CD, 0x00D4, 0x00CA, 0x00D2, 0x00C8 };
/* dumplt (6 chars) — Dumplt */
static const wchar_t _p_dumplt[] = { 0x00D3, 0x00CD, 0x00D4, 0x00CA, 0x00D7, 0x00C8 };
/* ftkimager (9 chars) — FTK Imager */
static const wchar_t _p_ftkimager[] = { 0x00D1, 0x00CC, 0x00D2, 0x00D3, 0x00D6, 0x00DD, 0x00DA, 0x00DB, 0x00CD };
/* belkasoft (9 chars) — Belkasoft Live RAM Capturer */
static const wchar_t _p_belkasoft[] = { 0x00D5, 0x00DD, 0x00D5, 0x00D1, 0x00DA, 0x00CF, 0x00D2, 0x00D8, 0x00CB };
/* magnetramcapture (16 chars) — Magnet RAM Capture */
static const wchar_t _p_magnetramcapture[] = { 0x00DA, 0x00D9, 0x00DE, 0x00D4, 0x00DE, 0x00C8, 0x00CF, 0x00DF, 0x00D2, 0x00A3, 0x00A0, 0x00B2, 0x00B7, 0x00B1, 0x00B7, 0x00A3 };
/* osforensics (11 chars) — OSForensics */
static const wchar_t _p_osforensics[] = { 0x00D8, 0x00CB, 0x00DF, 0x00D5, 0x00C9, 0x00D9, 0x00D3, 0x00CD, 0x00D6, 0x00A3, 0x00B2 };
/* redline (7 chars) — Redline */
static const wchar_t _p_redline[] = { 0x00C5, 0x00DD, 0x00DD, 0x00D6, 0x00D2, 0x00D2, 0x00D8 };
/* f-response (10 chars) — F-Response */
static const wchar_t _p_f_response[] = { 0x00D1, 0x0095, 0x00CB, 0x00DF, 0x00C8, 0x00CC, 0x00D2, 0x00D0, 0x00CC, 0x00A5 };
/* passware (8 chars) — Passware Bootable Memory Imager */
static const wchar_t _p_passware[] = { 0x00C7, 0x00D9, 0x00CA, 0x00C9, 0x00CC, 0x00DD, 0x00CF, 0x00DB };
/* surge (5 chars) — Surge Collect */
static const wchar_t _p_surge[] = { 0x00C4, 0x00CD, 0x00CB, 0x00DD, 0x00DE };
/* win64dd (7 chars) — win64dd */
static const wchar_t _p_win64dd[] = { 0x00C0, 0x00D1, 0x00D7, 0x008C, 0x008F, 0x00D8, 0x00D9 };
/* winmemreader (12 chars) — Windows Memory Reader */
static const wchar_t _p_winmemreader[] = { 0x00C0, 0x00D1, 0x00D7, 0x00D7, 0x00DE, 0x00D1, 0x00CF, 0x00DB, 0x00DE, 0x00A4, 0x00A4, 0x00B0 };
/* livekd (6 chars) — LiveKd */
static const wchar_t _p_livekd[] = { 0x00DB, 0x00D1, 0x00CF, 0x00DF, 0x00D0, 0x00D8 };
/* procexp (7 chars) — Process Explorer */
static const wchar_t _p_procexp[] = { 0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DE, 0x00C4, 0x00CD };
/* comsvcs (7 chars) — comsvcs.dll */
static const wchar_t _p_comsvcs[] = { 0x00D4, 0x00D7, 0x00D4, 0x00C9, 0x00CD, 0x00DF, 0x00CE };
/* userdump (8 chars) — userdump.exe */
static const wchar_t _p_userdump[] = { 0x00C2, 0x00CB, 0x00DC, 0x00C8, 0x00DF, 0x00C9, 0x00D0, 0x00CE };
/* dumpchk (7 chars) — DumpChk */
static const wchar_t _p_dumpchk[] = { 0x00D3, 0x00CD, 0x00D4, 0x00CA, 0x00D8, 0x00D4, 0x00D6 };
/* taskmgr (7 chars) — Task Manager */
static const wchar_t _p_taskmgr[] = { 0x00C3, 0x00D9, 0x00CA, 0x00D1, 0x00D6, 0x00DB, 0x00CF };
/* rekall (6 chars) — Rekall */
static const wchar_t _p_rekall[] = { 0x00C5, 0x00DD, 0x00D2, 0x00DB, 0x00D7, 0x00D0 };
/* memprocfs (9 chars) — MemProcFS */
static const wchar_t _p_memprocfs[] = { 0x00DA, 0x00DD, 0x00D4, 0x00CA, 0x00C9, 0x00D3, 0x00DE, 0x00D8, 0x00CC };
/* dumpulator (10 chars) — dumpulator */
static const wchar_t _p_dumpulator[] = { 0x00D3, 0x00CD, 0x00D4, 0x00CA, 0x00CE, 0x00D0, 0x00DC, 0x00CA, 0x00D0, 0x00B2 };
/* blacklight (10 chars) — BlackLight */
static const wchar_t _p_blacklight[] = { 0x00D5, 0x00D4, 0x00D8, 0x00D9, 0x00D0, 0x00D0, 0x00D4, 0x00D9, 0x00D7, 0x00B4 };
/* wdbgark (7 chars) — WDBGARK */
static const wchar_t _p_wdbgark[] = { 0x00C0, 0x00DC, 0x00DB, 0x00DD, 0x00DA, 0x00CE, 0x00D6 };
/* pymemoryeditor (14 chars) — PyMemoryEditor */
static const wchar_t _p_pymemoryeditor[] = { 0x00C7, 0x00C1, 0x00D4, 0x00DF, 0x00D6, 0x00D3, 0x00CF, 0x00C7, 0x00DA, 0x00A4, 0x00A8, 0x00B6, 0x00AC, 0x00B6 };
/* pymem (5 chars) — pymem */
static const wchar_t _p_pymem[] = { 0x00C7, 0x00C1, 0x00D4, 0x00DF, 0x00D6 };
/* collect-memorydump (18 chars) — Collect-MemoryDump */
static const wchar_t _p_collect_memorydump[] = { 0x00D4, 0x00D7, 0x00D5, 0x00D6, 0x00DE, 0x00DF, 0x00C9, 0x0093, 0x00D2, 0x00A5, 0x00AC, 0x00AD, 0x00B1, 0x00BD, 0x00A1, 0x00B3, 0x00AA, 0x00B8 };
/* memprocfs-analyzer (18 chars) — MemProcFS-Analyzer */
static const wchar_t _p_memprocfs_analyzer[] = { 0x00DA, 0x00DD, 0x00D4, 0x00CA, 0x00C9, 0x00D3, 0x00DE, 0x00D8, 0x00CC, 0x00ED, 0x00A0, 0x00AC, 0x00A2, 0x00A8, 0x00BC, 0x00BC, 0x00A2, 0x00BA };
/* memoryinvestigator (18 chars) — MemoryInvestigator */
static const wchar_t _p_memoryinvestigator[] = { 0x00DA, 0x00DD, 0x00D4, 0x00D5, 0x00C9, 0x00C5, 0x00D4, 0x00D0, 0x00C9, 0x00A5, 0x00B2, 0x00B6, 0x00AA, 0x00A3, 0x00A4, 0x00B2, 0x00A8, 0x00BA };
/* process-dump (12 chars) — Process-Dump */
static const wchar_t _p_process_dump[] = { 0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DE, 0x00CF, 0x00CE, 0x0093, 0x00DB, 0x00B5, 0x00AC, 0x00B2 };
/* memdump (7 chars) — memdump */
static const wchar_t _p_memdump[] = { 0x00DA, 0x00DD, 0x00D4, 0x00DE, 0x00CE, 0x00D1, 0x00CD };
/* memory-dumper (13 chars) — memory-dumper */
static const wchar_t _p_memory_dumper[] = { 0x00DA, 0x00DD, 0x00D4, 0x00D5, 0x00C9, 0x00C5, 0x0090, 0x00DA, 0x00CA, 0x00AD, 0x00B1, 0x00A7, 0x00B1 };
/* process-dumper (14 chars) — Process-Dumper */
static const wchar_t _p_process_dumper[] = { 0x00C7, 0x00CA, 0x00D6, 0x00D9, 0x00DE, 0x00CF, 0x00CE, 0x0093, 0x00DB, 0x00B5, 0x00AC, 0x00B2, 0x00A6, 0x00B6 };
/* nemesis (7 chars) — Nemesis */
static const wchar_t _p_nemesis[] = { 0x00D9, 0x00DD, 0x00D4, 0x00DF, 0x00C8, 0x00D5, 0x00CE };
/* dumpr (5 chars) — dumpr */
static const wchar_t _p_dumpr[] = { 0x00D3, 0x00CD, 0x00D4, 0x00CA, 0x00C9 };
/* firedumper (10 chars) — FireDumper */
static const wchar_t _p_firedumper[] = { 0x00D1, 0x00D1, 0x00CB, 0x00DF, 0x00DF, 0x00C9, 0x00D0, 0x00CE, 0x00DA, 0x00B2 };
/* minidump (8 chars) — MiniDump */
static const wchar_t _p_minidump[] = { 0x00DA, 0x00D1, 0x00D7, 0x00D3, 0x00DF, 0x00C9, 0x00D0, 0x00CE };
/* livedump (8 chars) — LiveDump */
static const wchar_t _p_livedump[] = { 0x00DB, 0x00D1, 0x00CF, 0x00DF, 0x00DF, 0x00C9, 0x00D0, 0x00CE };
/* pe-sieve (8 chars) — PE-sieve */
static const wchar_t _p_pe_sieve[] = { 0x00C7, 0x00DD, 0x0094, 0x00C9, 0x00D2, 0x00D9, 0x00CB, 0x00DB };

/* cvc5 (4 chars) — cvc5 */
static const wchar_t _p_cvc5[] = { 0x00D4, 0x00CE, 0x00DA, 0x008F };
/* yices (5 chars) — Yices 2 */
static const wchar_t _p_yices[] = { 0x00CE, 0x00D1, 0x00DA, 0x00DF, 0x00C8 };
/* mathsat (7 chars) — MathSAT5 */
static const wchar_t _p_mathsat[] = { 0x00DA, 0x00D9, 0x00CD, 0x00D2, 0x00C8, 0x00DD, 0x00C9 };
/* boolector (9 chars) — Boolector */
static const wchar_t _p_boolector[] = { 0x00D5, 0x00D7, 0x00D6, 0x00D6, 0x00DE, 0x00DF, 0x00C9, 0x00D1, 0x00CD };
/* bitwuzla (8 chars) — Bitwuzla */
static const wchar_t _p_bitwuzla[] = { 0x00D5, 0x00D1, 0x00CD, 0x00CD, 0x00CE, 0x00C6, 0x00D1, 0x00DF };
/* stp (3 chars) — STP (Simple Theorem Prover) */
static const wchar_t _p_stp[] = { 0x00C4, 0x00CC, 0x00C9 };
/* opensmt (7 chars) — OpenSMT */
static const wchar_t _p_opensmt[] = { 0x00D8, 0x00C8, 0x00DC, 0x00D4, 0x00C8, 0x00D1, 0x00C9 };
/* smt-rat (7 chars) — SMT-RAT */
static const wchar_t _p_smt_rat[] = { 0x00C4, 0x00D5, 0x00CD, 0x0097, 0x00C9, 0x00DD, 0x00C9 };
/* z3str3 (6 chars) — Z3str3 */
static const wchar_t _p_z3str3[] = { 0x00CD, 0x008B, 0x00CA, 0x00CE, 0x00C9, 0x008F };
/* alt-ergo (8 chars) — Alt-Ergo */
static const wchar_t _p_alt_ergo[] = { 0x00D6, 0x00D4, 0x00CD, 0x0097, 0x00DE, 0x00CE, 0x00DA, 0x00D1 };
/* z3-resolver (11 chars) — z3-resolver */
static const wchar_t _p_z3_resolver[] = { 0x00CD, 0x008B, 0x0094, 0x00C8, 0x00DE, 0x00CF, 0x00D2, 0x00D2, 0x00C9, 0x00A5, 0x00B3 };

/* peid (4 chars) — PEiD */
static const wchar_t _p_peid[] = { 0x00C7, 0x00DD, 0x00D0, 0x00DE };

/* Table of all monitored process name fragments.
 * label field is only compiled into DEBUG builds for human-readable logging.
 * In RELEASE (NDEBUG), the label strings are absent from .rdata. */
#ifndef NDEBUG
typedef struct { const wchar_t *enc; int len; const char *label; } ARE_ENTRY;
#  define ARE_LABEL(x) , x
#else
typedef struct { const wchar_t *enc; int len; } ARE_ENTRY;
#  define ARE_LABEL(x)
#endif

static const ARE_ENTRY s_areTable[] = {
    { _p_ida,      7  ARE_LABEL("IDA Pro")           },
    { _p_idag64,   10 ARE_LABEL("IDA GUI 64")        },
    { _p_ghidra,   6  ARE_LABEL("Ghidra")            },
    { _p_reclass,  7  ARE_LABEL("ReClass")           },
    { _p_x64dbg,   10 ARE_LABEL("x64dbg")            },
    { _p_x32dbg,   10 ARE_LABEL("x32dbg")            },
    { _p_phacker,  13 ARE_LABEL("Process Hacker")    },
    { _p_hxd,      3  ARE_LABEL("HxD")              },
    { _p_apimon,   10 ARE_LABEL("API Monitor")       },
    { _p_dnspy,    5  ARE_LABEL("dnSpy")             },
    { _p_ollydbg,  7  ARE_LABEL("OllyDbg")           },
    { _p_windbg,   6  ARE_LABEL("WinDbg")            },
    { _p_immunit,  7  ARE_LABEL("Immunity Debugger") },
    { _p_binja,    11 ARE_LABEL("Binary Ninja")      },
    { _p_cutter,   6  ARE_LABEL("Cutter (Rizin)")    },
    { _p_die,      5  ARE_LABEL("Detect It Easy")    },
    { _p_pebear,   7  ARE_LABEL("PE-bear")           },
    { _p_cffexpl,  9  ARE_LABEL("CFF Explorer")      },
    { _p_scylla,   6  ARE_LABEL("Scylla")            },
    { _p_pestudio, 8  ARE_LABEL("pestudio")          },
    { _p_reshack,  7  ARE_LABEL("Resource Hacker")   },
    { _p_radare,   6  ARE_LABEL("radare2")           },
    { _p_fiddler,  7  ARE_LABEL("Fiddler")           },
    { _p_ksdumper, 8  ARE_LABEL("KsDumper")          },
    { _p_megadumper, 10 ARE_LABEL("MegaDumper")      },
    { _p_extremedumper, 13 ARE_LABEL("ExtremeDumper") },
    { _p_procdump, 8  ARE_LABEL("ProcDump")          },
    { _p_petools,  7  ARE_LABEL("PE Tools")          },
    { _p_pethief,  7  ARE_LABEL("PE Thief")          },
    { _p_titanhide, 9  ARE_LABEL("TitanHide")        },
    { _p_procdump2, 11 ARE_LABEL("Process Dump")     },
    { _p_netdumper, 9  ARE_LABEL("NetDumper")        },
    { _p_scyllahide, 10 ARE_LABEL("ScyllaHide")      },
    { _p_kdu,      3  ARE_LABEL("KDU")               },
    { _p_kernel_mode_ram, 15 ARE_LABEL("kernel-mode-ram-read-write") },
    { _p_ppldump,  7  ARE_LABEL("PPLdump")           },
    { _p_pplblade, 8  ARE_LABEL("PPLBlade")          },
    { _p_kvc,      3  ARE_LABEL("KVC")               },
    { _p_process_memory_dumper, 21 ARE_LABEL("Process-Memory-Dumper") },
    { _p_libmem,   6  ARE_LABEL("libmem")            },
    { _p_poggers,  7  ARE_LABEL("poggers")           },
    { _p_arymem,   6  ARE_LABEL("AryMem")            },
    { _p_unmapper, 8  ARE_LABEL("Unmapper")          },
    { _p_memory_mirror, 13 ARE_LABEL("memory-mirror") },
    { _p_sonar,    5  ARE_LABEL("Sonar")             },
    { _p_fridump,  7  ARE_LABEL("fridump3")          },
    { _p_volatility, 10 ARE_LABEL("Volatility3")     },
    { _p_winpmem,  7  ARE_LABEL("WinPmem")           },
    { _p_dumpit,   6  ARE_LABEL("DumpIt")            },
    { _p_dumplt,   6  ARE_LABEL("Dumplt")            },
    { _p_ftkimager, 9  ARE_LABEL("FTK Imager")       },
    { _p_belkasoft, 9  ARE_LABEL("Belkasoft Live RAM Capturer") },
    { _p_magnetramcapture, 16 ARE_LABEL("Magnet RAM Capture") },
    { _p_osforensics, 11 ARE_LABEL("OSForensics")     },
    { _p_redline,  7  ARE_LABEL("Redline")           },
    { _p_f_response, 10 ARE_LABEL("F-Response")      },
    { _p_passware, 8  ARE_LABEL("Passware Bootable Memory Imager") },
    { _p_surge,    5  ARE_LABEL("Surge Collect")     },
    { _p_win64dd,  7  ARE_LABEL("win64dd")           },
    { _p_winmemreader, 12 ARE_LABEL("Windows Memory Reader") },
    { _p_livekd,   6  ARE_LABEL("LiveKd")            },
    { _p_procexp,  7  ARE_LABEL("Process Explorer")  },
    { _p_comsvcs,  7  ARE_LABEL("comsvcs.dll")       },
    { _p_userdump, 8  ARE_LABEL("userdump.exe")      },
    { _p_dumpchk,  7  ARE_LABEL("DumpChk")           },
    { _p_taskmgr,  7  ARE_LABEL("Task Manager")      },
    { _p_rekall,   6  ARE_LABEL("Rekall")            },
    { _p_memprocfs, 9  ARE_LABEL("MemProcFS")        },
    { _p_dumpulator, 10 ARE_LABEL("dumpulator")      },
    { _p_blacklight, 10 ARE_LABEL("BlackLight")      },
    { _p_wdbgark,  7  ARE_LABEL("WDBGARK")           },
    { _p_pymemoryeditor, 14 ARE_LABEL("PyMemoryEditor") },
    { _p_pymem,    5  ARE_LABEL("pymem")             },
    { _p_collect_memorydump, 18 ARE_LABEL("Collect-MemoryDump") },
    { _p_memprocfs_analyzer, 18 ARE_LABEL("MemProcFS-Analyzer") },
    { _p_memoryinvestigator, 18 ARE_LABEL("MemoryInvestigator") },
    { _p_process_dump, 12 ARE_LABEL("Process-Dump")  },
    { _p_memdump,  7  ARE_LABEL("memdump")           },
    { _p_memory_dumper, 13 ARE_LABEL("memory-dumper") },
    { _p_process_dumper, 14 ARE_LABEL("Process-Dumper") },
    { _p_nemesis,  7  ARE_LABEL("Nemesis")           },
    { _p_dumpr,    5  ARE_LABEL("dumpr")             },
    { _p_firedumper, 10 ARE_LABEL("FireDumper")      },
    { _p_minidump, 8  ARE_LABEL("MiniDump")          },
    { _p_livedump, 8  ARE_LABEL("LiveDump")          },
    { _p_pe_sieve, 8  ARE_LABEL("PE-sieve")          },
    { _p_cvc5        , 4  ARE_LABEL("cvc5") },
    { _p_yices       , 5  ARE_LABEL("Yices 2") },
    { _p_mathsat     , 7  ARE_LABEL("MathSAT5") },
    { _p_boolector   , 9  ARE_LABEL("Boolector") },
    { _p_bitwuzla    , 8  ARE_LABEL("Bitwuzla") },
    { _p_stp         , 3  ARE_LABEL("STP (Simple Theorem Prover)") },
    { _p_opensmt     , 7  ARE_LABEL("OpenSMT") },
    { _p_smt_rat     , 7  ARE_LABEL("SMT-RAT") },
    { _p_z3str3      , 6  ARE_LABEL("Z3str3") },
    { _p_alt_ergo    , 8  ARE_LABEL("Alt-Ergo") },
    { _p_z3_resolver , 11 ARE_LABEL("z3-resolver") },
    { _p_peid        , 4  ARE_LABEL("PEiD") },
};
#define ARE_TABLE_COUNT (sizeof(s_areTable)/sizeof(s_areTable[0]))

/* ── Case-insensitive wide substring search ────────────────────────────── */
static BOOL _wcsContainsI(const wchar_t *haystack, const wchar_t *needle, int needleLen) {
    int hLen = (int)wcslen(haystack);
    if (hLen < needleLen) return FALSE;
    for (int i = 0; i <= hLen - needleLen; i++) {
        BOOL match = TRUE;
        for (int j = 0; j < needleLen; j++) {
            wchar_t a = haystack[i + j];
            wchar_t b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/* ── Core scan: returns label of detected tool (DEBUG), or "1" sentinel (RELEASE).
 * Uses SysNtQuerySystemInformation (direct syscall) instead of
 * CreateToolhelp32Snapshot + Process32NextW to avoid kernel32 hooks. */
static const char* AntiRE_Scan(void) {
    /* Allocate a growing buffer for SystemProcessInformation (class 5). */
    ULONG bufSize = 0x20000; /* 128 KB initial */
    BYTE *buf = NULL;
    NTSTATUS st;
    for (int tries = 0; tries < 6; tries++) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (!buf) return NULL;
        ULONG retLen = 0;
        st = SysNtQuerySystemInformation(5 /* SystemProcessInformation */,
                                         buf, bufSize, &retLen);
        if (NT_SUCCESS(st)) break;
        if ((ULONG)st == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
            bufSize = retLen + 0x4000; continue;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    if (!buf || !NT_SUCCESS(st)) {
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }

    const char *detected = NULL;
    BYTE *p = buf;
    for (;;) {
        /* SYSTEM_PROCESS_INFORMATION layout (x64):
         *   +0x00 ULONG  NextEntryOffset
         *   +0x04 ULONG  NumberOfThreads
         *   +0x38 UNICODE_STRING ImageName  (Length/MaxLen at +0x38, Buffer* at +0x40) */
        ULONG next = *(ULONG*)p;
        USHORT nameLen  = *(USHORT*)(p + 0x38);
        PWSTR  namePtr  = *(PWSTR* )(p + 0x40);
        if (namePtr && nameLen > 0 && nameLen <= 256) {
            /* Copy to stack-local buffer for safe access */
            int nChars = nameLen / 2;
            if (nChars > 128) nChars = 128;
            wchar_t procName[129] = {0};
            for (int c = 0; c < nChars; c++) procName[c] = namePtr[c];
            procName[nChars] = 0;

            wchar_t decBuf[32];
            for (int t = 0; t < (int)ARE_TABLE_COUNT; t++) {
                _areDec(s_areTable[t].enc, s_areTable[t].len, decBuf);
                if (_wcsContainsI(procName, decBuf, s_areTable[t].len)) {
#ifndef NDEBUG
                    detected = s_areTable[t].label;
#else
                    detected = "1";
#endif
                    SecureZeroMemory(decBuf, sizeof(decBuf));
                    break;
                }
                SecureZeroMemory(decBuf, sizeof(decBuf));
            }
        }
        if (detected || next == 0) break;
        p += next;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    return detected;
}

/* ── Discord Webhook notification ────────────────────────────────────────
 * Sends a JSON embed to a Discord channel via HTTPS POST.
 * ANTIRE_WEBHOOK_ID and ANTIRE_WEBHOOK_TOKEN are set in b.bat.
 * If not defined, notification is silently skipped.                      */
#if defined(ANTIRE_WEBHOOK_ID) && defined(ANTIRE_WEBHOOK_TOKEN)
#include <winhttp.h>

static void AntiRE_NotifyDiscord(const char *toolName) {
    /* Build HWID string (same logic as keyauth.c) */
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    SYSTEM_INFO si; GetSystemInfo(&si);
    char userName[64] = {0}; DWORD userSz = sizeof(userName);
    GetUserNameA(userName, &userSz);
    /* P8: SeraphHash32 \u2014 sem FNV-1a constants (0x811C9DC5/0x01000193 s\u00e3o YARA targets) */
    DWORD userHash = 0xA3C59F17u;
    for (int i = 0; userName[i]; i++) { userHash ^= (BYTE)userName[i]; userHash=(userHash<<5)|(userHash>>27); userHash *= 0x27D4EB2Fu; }

    char hwid[40];
    sprintf(hwid, "%08X%08X%08X", volSerial, userHash,
            (DWORD)si.dwNumberOfProcessors ^ (DWORD)si.dwPageSize);

    /* Get extended hardware fingerprint and BIOS serials */
    char extHwid[256] = {0};
    SeraphBanMarker_GetHardwareFingerprint(extHwid, sizeof(extHwid));

    /* Build JSON payload */
    /* Build JSON payload — assembled from XOR fragments to avoid .rdata exposure */
    /* XOR key 0x19 fragments: */
    /* "{\"embeds\":[{\"title\":\"\\u26a0\\ufe0f AntiRE Detection\",\"color\":16711680,\"fields\":[" */
    static const char _jA[]={0x3B,0x66,0x72,0x7D,0x7A,0x7B,0x6C,0x45,0x66,0x7B,0x76,0x6B,0x73,0x7A,0x6C,0x45,0x66,0x6B,0x76,0x7D,0x7A,0x7B,0x6C,0x45,0x66,0x7D,0x7A,0x7B,0x6C,0x72,0x69,0x3B,0x7E,0x73,0x27,0x27,0x7E,0x26,0x26,0x7F,0x7C,0x6C,0x7A,0x47,0x72,0x7C,0x70,0x73,0x6C,0x5F,0x7A,0x66,0x7A,0x7C,0x6B,0x76,0x70,0x71,0x3B,0x6A,0x70,0x73,0x70,0x6D,0x3A,0x26,0x20,0x2F,0x2E,0x2E,0x26,0x21,0x23,0x3B,0x6D,0x76,0x7A,0x73,0x7B,0x6C,0x72,0x69,0x3B};
    /* "{\"name\":\"Tool/Reason\",\"value\":\"%s\",\"inline\":true}," */
    static const char _jB[]={0x7B,0x66,0x7B,0x7A,0x72,0x7C,0x3B,0x71,0x7E,0x7E,0x6B,0x4C,0x3A,0x4F,0x7A,0x70,0x6D,0x70,0x71,0x7B,0x66,0x7B,0x60,0x7E,0x73,0x6E,0x7A,0x3B,0x71,0x7E,0x7E,0x6A,0x71,0x7A,0x6D,0x70,0x71,0x7A,0x75,0x7B,0x66,0x7B,0x6A,0x71,0x7C,0x70,0x71,0x7A,0x3A,0x6D,0x7D,0x6A,0x7A,0x7D,0x7D};
    /* "{\"name\":\"HWID\",\"value\":\"`%s`\",\"inline\":true}," */
    static const char _jC[]={0x7B,0x66,0x7B,0x7A,0x72,0x7C,0x3B,0x71,0x7E,0x7E,0x5F,0x40,0x50,0x52,0x7B,0x66,0x7B,0x60,0x7E,0x73,0x6E,0x7A,0x3B,0x71,0x7E,0x7E,0x7F,0x3A,0x71,0x3A,0x7F,0x7B,0x66,0x7B,0x6A,0x71,0x7C,0x70,0x71,0x7A,0x3A,0x6D,0x7D,0x6A,0x7A,0x7D,0x7D};
    /* "{\"name\":\"User\",\"value\":\"`%s`\",\"inline\":true}," */
    static const char _jD[]={0x7B,0x66,0x7B,0x7A,0x72,0x7C,0x3B,0x71,0x7E,0x7E,0x42,0x6E,0x7A,0x6F,0x7B,0x66,0x7B,0x60,0x7E,0x73,0x6E,0x7A,0x3B,0x71,0x7E,0x7E,0x7F,0x3A,0x71,0x3A,0x7F,0x7B,0x66,0x7B,0x6A,0x71,0x7C,0x70,0x71,0x7A,0x3A,0x6D,0x7D,0x6A,0x7A,0x7D,0x7D};
    /* "{\"name\":\"Extended HWID Components\",\"value\":\"`%s`\",\"inline\":false}," */
    static const char _jE[]={0x7B,0x66,0x7B,0x7A,0x72,0x7C,0x3B,0x71,0x7E,0x7E,0x52,0x61,0x6D,0x7A,0x71,0x7F,0x7A,0x7D,0x3A,0x5F,0x40,0x50,0x52,0x3A,0x54,0x76,0x70,0x6D,0x70,0x71,0x7A,0x71,0x6D,0x7A,0x7B,0x66,0x7B,0x60,0x7E,0x73,0x6E,0x7A,0x3B,0x71,0x7E,0x7E,0x7F,0x3A,0x71,0x3A,0x7F,0x7B,0x66,0x7B,0x6A,0x71,0x7C,0x70,0x71,0x7A,0x3A,0x7D,0x72,0x73,0x6C,0x7A,0x7D,0x7D};
    /* "{\"name\":\"Action\",\"value\":\"Banned + Ejected\",\"inline\":false}]}]}" */
    static const char _jF[]={0x7B,0x66,0x7B,0x7A,0x72,0x7C,0x3B,0x71,0x7E,0x7E,0x56,0x7A,0x6B,0x70,0x76,0x71,0x7B,0x66,0x7B,0x60,0x7E,0x73,0x6E,0x7A,0x3B,0x71,0x7E,0x7E,0x55,0x70,0x7D,0x7D,0x7A,0x7F,0x3A,0x3C,0x3A,0x52,0x73,0x7A,0x72,0x7D,0x7A,0x7F,0x7B,0x66,0x7B,0x6A,0x71,0x7C,0x70,0x71,0x7A,0x3A,0x7D,0x72,0x73,0x6C,0x7A,0x7D,0x7C,0x7D,0x7D,0x6C};

    /* Decode all fragments onto stack */
    #define _JD(arr, out) char out[sizeof(arr)]; { int _n=(int)sizeof(arr)-1; for(int _i=0;_i<_n;_i++) out[_i]=(char)((unsigned char)arr[_i]^0x19u); out[_n]=0; }
    _JD(_jA, _sA) _JD(_jB, _sB) _JD(_jC, _sC) _JD(_jD, _sD) _JD(_jE, _sE) _JD(_jF, _sF)
    #undef _JD

    char json[1536];
    char json_fmt[1024];
    snprintf(json_fmt, sizeof(json_fmt), "%s%s%s%s%s%s", _sA, _sB, _sC, _sD, _sE, _sF);
    sprintf(json, json_fmt, toolName, hwid, userName, extHwid);

    /* ──── Decode all string dependencies onto the stack at runtime ──────────────────────
     * Nothing touches .rdata: all names come from xor_strings.h arrays.     */
#define DECODE_WHOOK_A(arr) \
    char _dha_##arr[sizeof(arr)]; \
    { int _len = (int)sizeof(arr) - 1; \
      for (int _i = 0; _i < _len; _i++) { \
          UINT32 v0 = ((UINT32)_i ^ SERAPH_KEY1); \
          UINT32 v1 = v0 + SERAPH_KEY2; \
          int rot = (int)((SERAPH_KEY3 + (UINT32)_i) & 31); \
          UINT32 v2 = (v1 << rot) | (v1 >> (32 - rot)); \
          UINT32 v3 = v2 ^ SERAPH_KEY4; \
          unsigned char kb = (unsigned char)(v3 & 0xFF); \
          _dha_##arr[_i] = (char)((arr)[_i] ^ kb); \
      } \
      _dha_##arr[sizeof(arr)-1] = '\0'; }

#define DECODE_WHOOK_W(arr) \
    wchar_t _dhw_##arr[sizeof(arr)/sizeof(wchar_t)]; \
    { int _wn = (int)(sizeof(arr)/sizeof(wchar_t)) - 1; \
      for (int _wi = 0; _wi < _wn; _wi++) { \
          UINT32 v0 = ((UINT32)_wi ^ SERAPH_KEY1); \
          UINT32 v1 = v0 + SERAPH_KEY2; \
          int rot = (int)((SERAPH_KEY3 + (UINT32)_wi) & 31); \
          UINT32 v2 = (v1 << rot) | (v1 >> (32 - rot)); \
          UINT32 v3 = v2 ^ SERAPH_KEY4; \
          wchar_t kw = (wchar_t)(v3 & 0xFFFF); \
          _dhw_##arr[_wi] = (wchar_t)((arr)[_wi] ^ kw); \
      } \
      _dhw_##arr[_wn] = L'\0'; }

    /* Decode DLL name and load it */
    DECODE_WHOOK_W(ENC_winhttp_dll)
    HMODULE wh = (HMODULE)SeraphLoadDll(_dhw_ENC_winhttp_dll, NULL);
    if (!wh) goto _notify_cleanup;

    /* Decode function names */
    DECODE_WHOOK_A(ENC_WinHttpOpen)
    DECODE_WHOOK_A(ENC_WinHttpConnect)
    DECODE_WHOOK_A(ENC_WinHttpOpenRequest)
    DECODE_WHOOK_A(ENC_WinHttpSendRequest)
    DECODE_WHOOK_A(ENC_WinHttpReceiveResponse)
    DECODE_WHOOK_A(ENC_WinHttpCloseHandle)
    DECODE_WHOOK_A(ENC_WinHttpSetTimeouts)

    typedef HINTERNET(WINAPI*tOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
    typedef HINTERNET(WINAPI*tConn)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
    typedef HINTERNET(WINAPI*tReq)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
    typedef BOOL(WINAPI*tSend)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
    typedef BOOL(WINAPI*tRecv)(HINTERNET,LPVOID);
    typedef BOOL(WINAPI*tClose)(HINTERNET);
    typedef BOOL(WINAPI*tSetTO)(HINTERNET,int,int,int,int);

    tOpen  fO  = (tOpen) GetProcAddress(wh, _dha_ENC_WinHttpOpen);
    tConn  fC  = (tConn) GetProcAddress(wh, _dha_ENC_WinHttpConnect);
    tReq   fR  = (tReq)  GetProcAddress(wh, _dha_ENC_WinHttpOpenRequest);
    tSend  fS  = (tSend) GetProcAddress(wh, _dha_ENC_WinHttpSendRequest);
    tRecv  fRR = (tRecv) GetProcAddress(wh, _dha_ENC_WinHttpReceiveResponse);
    tClose fCl = (tClose)GetProcAddress(wh, _dha_ENC_WinHttpCloseHandle);
    tSetTO fTO = (tSetTO)GetProcAddress(wh, _dha_ENC_WinHttpSetTimeouts);
    if (!fO||!fC||!fR||!fS||!fRR||!fCl) { FreeLibrary(wh); goto _notify_cleanup; }

    /* Decode User-Agent and open session */
    DECODE_WHOOK_W(ENC_discord_ua)
    HINTERNET hS = fO(_dhw_ENC_discord_ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { FreeLibrary(wh); goto _notify_cleanup; }

    /* Fix #9: set 5-second timeouts to avoid hanging the antire thread */
    if (fTO) fTO(hS, 5000, 5000, 5000, 5000);

    /* Decode host and connect */
    DECODE_WHOOK_W(ENC_discord_host)
    HINTERNET hC = fC(hS, _dhw_ENC_discord_host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hC) { fCl(hS); FreeLibrary(wh); goto _notify_cleanup; }

    /* Build path: /api/webhooks/ID/TOKEN — prefix decoded from XOR array */
    DECODE_WHOOK_W(ENC_webhooks_path_pfx)
    WCHAR path[512];
    _snwprintf_s(path, 512, _TRUNCATE, L"%s%s/%s",
                 _dhw_ENC_webhooks_path_pfx, ANTIRE_WEBHOOK_ID, ANTIRE_WEBHOOK_TOKEN);

    /* Decode method and open request */
    DECODE_WHOOK_W(ENC_POST)
    HINTERNET hR = fR(hC, _dhw_ENC_POST, path, NULL, WINHTTP_NO_REFERER,
                      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (hR) {
        /* Decode Content-Type header */
        DECODE_WHOOK_W(ENC_discord_ct_json)
        DWORD bodyLen = (DWORD)strlen(json);
        fS(hR, _dhw_ENC_discord_ct_json, (DWORD)-1,
           (LPVOID)json, bodyLen, bodyLen, 0);
        fRR(hR, NULL);
        fCl(hR);
    }
    fCl(hC); fCl(hS);
    /* Don't FreeLibrary — we're about to ExitProcess anyway */

#undef DECODE_WHOOK_A
#undef DECODE_WHOOK_W

_notify_cleanup:
    /* Zero sensitive stack buffers */
    SecureZeroMemory(hwid, sizeof(hwid));
    SecureZeroMemory(userName, sizeof(userName));
    SecureZeroMemory(json, sizeof(json));
    return;
}
#else
static void AntiRE_NotifyDiscord(const char *toolName) { (void)toolName; }
#endif

/* ── Thread state ────────────────────────────────────────────────────────── */
static volatile LONG s_areRunning = 0;
static HANDLE        s_areThread  = NULL;

static DWORD WINAPI AntiRE_Thread(LPVOID param) {
    (void)param;

    /* Initial grace period — let the user settle in */
    SeraphSleep(5000);

    while (InterlockedCompareExchange(&s_areRunning, 1, 1) == 1) {
        const char *tool = AntiRE_Scan();
        if (tool) {
#ifdef NDEBUG
            /* ── RELEASE: notify + ban + delay + deject + exit ──────────── */
            /* 1. Discord notification (fire-and-forget) */
            AntiRE_NotifyDiscord(tool);

            /* 2. Ban the active session key */
            KeyAuth_BanCurrentKey();

            /* 3. Delay to obscure which check triggered */
            SeraphSleep(30000);

            /* 4. Deject from game */
            Attach_Invalidate();

            /* 5. Wipe saved credentials */
            {
                WCHAR credPath[MAX_PATH];
                GetEnvironmentVariableW(L"APPDATA", credPath, MAX_PATH);
                WCHAR dir[MAX_PATH]; wcscpy(dir, credPath);
                { static const unsigned short _pe[]={0xEB^0xA5,0xD4^0xA5,0xC8^0xA5,0xC7^0xA5,0xCA^0xA5,0xD6^0xA5,0xD1^0xA5,0xDA^0xA5,0x8A^0xA5,0x8A^0xA5,0xE1^0xA5,0xC0^0xA5,0xD2^0xA5,0xC4^0xA5,0xC7^0xA5,0xD1^0xA5,0xD6^0xA5};
                  wchar_t _pd[18]; for(int i=0;i<17;i++) _pd[i]=(wchar_t)(_pe[i]^0xA5u); _pd[17]=0;
                  wcscat(dir, _pd); }
                wcscpy(credPath, dir);
                { static const unsigned short _fe[]={0xEB^0xA5,0xC4^0xA5,0x8B^0xA5,0xC7^0xA5,0xC4^0xA5,0xD1^0xA5};
                  wchar_t _fd[7]; for(int i=0;i<6;i++) _fd[i]=(wchar_t)(_fe[i]^0xA5u); _fd[6]=0;
                  wcscat(credPath, _fd); }
                DeleteFileW(credPath);
            }

            /* 6. Silent exit */
            ExitProcess(0);
#else
            /* ── DEBUG: log only ────────────────────────────────────────── */
            char logBuf[128];
            sprintf(logBuf, "AntiRE: detected [%s] (debug — no action)", tool);
            WriteLogFile(logBuf);
#endif
        }
        /* Poll every 3 seconds */
        for (int i = 0; i < 30 && InterlockedCompareExchange(&s_areRunning, 1, 1) == 1; i++)
            SeraphSleep(100);
    }
    return 0;
}

static PVOID g_honeyPage = NULL;
static PVOID g_vehHandler = NULL;

static LONG CALLBACK AntiRe_VEH(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo && pExInfo->ExceptionRecord) {
        DWORD code = pExInfo->ExceptionRecord->ExceptionCode;
        if (code == STATUS_ACCESS_VIOLATION || code == STATUS_GUARD_PAGE_VIOLATION) {
            ULONG_PTR faultAddr = pExInfo->ExceptionRecord->ExceptionInformation[1];
            if (g_honeyPage && faultAddr >= (ULONG_PTR)g_honeyPage && faultAddr < ((ULONG_PTR)g_honeyPage + 4096)) {
#ifdef NDEBUG
                /* ── RELEASE: notify + ban + delay + exit ──────────── */
                { static const char _he[]={0xED,0xCA,0xCB,0xC0,0xDC,0xD5,0xCA,0xD1,0x85,0xE8,0xC0,0xC8,0xCA,0xD7,0xDC,0x85,0xF6,0xC6,0xC4,0xCB,0x85,0xE1,0xC0,0xD1,0xC0,0xC6,0xD1,0xC0,0xC1}; /* "Honeypot Memory Scan Detected" ^0xA5 */
                  char _hd[30]; for(int _i=0;_i<29;_i++) _hd[_i]=(char)((unsigned char)_he[_i]^0xA5u); _hd[29]=0;
                  AntiRE_NotifyDiscord(_hd); }
                KeyAuth_BanCurrentKey();
                SeraphSleep(15000);
                ExitProcess(0);
#else
                WriteLogFile("AntiRE VEH: Honeypot page read/write detected!");
#endif
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void AntiRE_Start(void) {
    if (InterlockedCompareExchange(&s_areRunning, 1, 0) != 0) return;

    /* Allocate honey page trap (PAGE_GUARD triggers exception on first read/write access) */
    g_honeyPage = SeraphVAlloc(4096, PAGE_READWRITE | PAGE_GUARD);
    if (g_honeyPage) {
        g_vehHandler = AddVectoredExceptionHandler(1, AntiRe_VEH);
    }

    s_areThread = SeraphCreateThread(AntiRE_Thread, NULL);
    if (!s_areThread) {
        InterlockedExchange(&s_areRunning, 0);
        if (g_vehHandler) {
            RemoveVectoredExceptionHandler(g_vehHandler);
            g_vehHandler = NULL;
        }
        if (g_honeyPage) {
            SeraphVFree(g_honeyPage);
            g_honeyPage = NULL;
        }
    }
}

void AntiRE_Stop(void) {
    InterlockedExchange(&s_areRunning, 0);
    if (s_areThread) {
        WaitForSingleObject(s_areThread, 3000);
        SysNtClose(s_areThread);
        s_areThread = NULL;
    }
    if (g_vehHandler) {
        RemoveVectoredExceptionHandler(g_vehHandler);
        g_vehHandler = NULL;
    }
    if (g_honeyPage) {
        SeraphVFree(g_honeyPage);
        g_honeyPage = NULL;
    }
}

