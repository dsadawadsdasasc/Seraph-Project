/* ============================================================
 * packetscan.c — DEVELOPMENT/RESEARCH TOOL ONLY.
 *
 * Este arquivo NÃO é compilado em builds de release.
 * Para habilitar, defina SERAPH_DEV_PACKETSCAN na linha de comando do compilador.
 * Nunca inclua esse define em b_release.bat.
 * ============================================================ */
#ifdef SERAPH_DEV_PACKETSCAN

/*
 * packetscan.c — hooks WS2_32!sendto in the game process and logs
 * outgoing UDP packets to packets.txt for offline inspection.
 *
 * Hook strategy: 15-byte overwrite at sendto using an absolute indirect
 * JMP (FF 25 00 00 00 00 [addr8]) so the code cave can be ANYWHERE in the
 * 64-bit address space — no ±2GB constraint.
 *
 * Two separate caves (found via CaveFinder_FindFirst, no distance limit):
 *   Data cave  (≥32 bytes)  — mailbox: enabled, hit counter, buf ptr, len
 *   Code cave  (≥64 bytes)  — shellcode + 15 stolen bytes + absolute JMP back
 *
 * sendto (x64): RCX=socket  RDX=buf(char*)  R8d=len  R9d=flags  ...
 *
 * Data cave layout:
 *   [0x00] UINT64 enabled  — 1 = hook active
 *   [0x08] UINT64 hit      — incremented by shellcode on each sendto call
 *   [0x10] UINT64 bufVA    — saved buf pointer (RDX)
 *   [0x18] UINT32 bufLen   — saved len (R8d)
 *   [0x1C] UINT32 _pad
 */

#include "packetscan.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "cave_finder.h"
#include "debug.h"

#include <stdio.h>
#include <string.h>

#define DEBUG_PS(fmt, ...) DEBUG_LOG_TO("packets.txt", "PS", fmt, ##__VA_ARGS__)

/* ── Mailbox offsets (data cave) ─────────────────────────────────── */
#define PS_CAVE_ENABLED  0x00
#define PS_CAVE_HIT      0x08
#define PS_CAVE_BUFS     0x10
#define PS_CAVE_NBUFS    0x18
#define PS_DATA_MIN      32

/* ── Code cave size ──────────────────────────────────────────────── */
/* shellcode 61 + padding = 64 */
#define PS_CODE_MIN      64

/* ── Stolen length: 4 complete prolog instructions = 3+4+4+4 = 15 ─ */
#define PS_STOLEN_LEN    15

/* Mailbox field names (reuse same offsets) */
#define PS_CAVE_BUFVA   PS_CAVE_BUFS
#define PS_CAVE_BUFLEN  PS_CAVE_NBUFS

/* ── State ───────────────────────────────────────────────────────── */
static UINT64 s_dataCaveVA = 0;   /* mailbox                         */
static UINT64 s_codeCaveVA = 0;   /* shellcode                       */
static UINT64 s_hookVA     = 0;   /* patched address (WSASendTo)     */
static UINT8  s_origBytes[PS_STOLEN_LEN] = {0};
static UINT64 s_lastHit    = 0;

/* Walk PEB InLoadOrderModuleList, return first cave >= minSize.
 * Skips the address skipCave (already used) and the module at skipBase. */
static UINT64 FindCaveAnywhere(UINT64 cr3, UINT64 peb,
                               UINT32 minSize, UINT64 skipCave, UINT64 skipBase)
{
    UINT64 ldr = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, peb + 0x18, &ldr, 8);
    BYOVD_UNLOCK();
    if (!ldr) { DEBUG_PS("FindCave: no Ldr"); return 0; }

    UINT64 head  = ldr + 0x10;  /* &PEB_LDR_DATA.InLoadOrderModuleList */
    UINT64 entry = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, head, &entry, 8);
    BYOVD_UNLOCK();

    int n = 0;
    while (entry && entry != head && n++ < 512) {
        UINT64 dllBase = 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, entry + 0x30, &dllBase, 8);
        BYOVD_UNLOCK();

        if (dllBase && dllBase != skipBase) {
            BYOVD_LOCK();
            UINT64 cave = CaveFinder_FindFirst(cr3, dllBase, minSize);
            BYOVD_UNLOCK();
            if (cave && cave != skipCave) {
                DEBUG_PS("FindCave(%u): 0x%I64X (dll=0x%I64X)", minSize, cave, dllBase);
                return cave;
            }
        }

        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, entry, &entry, 8);
        BYOVD_UNLOCK();
    }
    DEBUG_PS("FindCave(%u): not found after %d modules", minSize, n);
    return 0;
}

/* ── Helpers ─────────────────────────────────────────────────────── */
/* Write a 14-byte absolute indirect JMP: FF 25 00 00 00 00 [target8] */
static void WriteAbsJmp(UINT8 *buf, UINT64 target)
{
    buf[0]=0xFF; buf[1]=0x25;
    buf[2]=0x00; buf[3]=0x00; buf[4]=0x00; buf[5]=0x00;
    *(UINT64*)(buf+6) = target;
}

/* ── Shellcode builder ───────────────────────────────────────────── */
/*
 * At WSASendTo entry (Windows x64):
 *   RCX=socket  RDX=lpBuffers  R8=dwBufferCount  R9=lpNumBytesSent
 *
 * The shellcode saves RDX and R8, checks the enabled flag in the data cave,
 * increments the hit counter, and saves both args to the mailbox.
 * All clobbered registers are fully preserved.
 *
 * Return: 14-byte absolute JMP to hookVA + PS_STOLEN_LEN.
 */
/*
 * Minimal shellcode: 61 bytes total.
 * sendto args: RDX = buf (char*), R8d = len.
 * Neither is touched by the 4 stolen prolog instructions (which only save
 * callee-saved regs to stack), so both are valid when we read them.
 */
static UINT32 BuildSC(UINT8 *sc, UINT64 mailboxVA, UINT64 hookVA,
                      const UINT8 *stolen)
{
    UINT32 i = 0;

    sc[i++]=0x53;                          /* push rbx             (1) */
    sc[i++]=0x9C;                          /* pushfq               (1) */

    sc[i++]=0x48; sc[i++]=0xBB;            /* mov rbx, mailboxVA  (10) */
    *(UINT64*)(&sc[i]) = mailboxVA; i+=8;

    sc[i++]=0x48; sc[i++]=0x83; sc[i++]=0x3B; sc[i++]=0x00; /* cmp qword[rbx],0  (4) */
    UINT32 jePos = i;
    sc[i++]=0x74; sc[i++]=0x00;            /* je .done (fixup)     (2) */

    sc[i++]=0x48; sc[i++]=0xFF; sc[i++]=0x43; sc[i++]=0x08; /* inc qword[rbx+8]  (4) */
    sc[i++]=0x48; sc[i++]=0x89; sc[i++]=0x53; sc[i++]=0x10; /* mov [rbx+10],rdx  (4) */
    sc[i++]=0x44; sc[i++]=0x89; sc[i++]=0x43; sc[i++]=0x18; /* mov [rbx+18],r8d  (4) */

    sc[jePos+1] = (UINT8)(i - jePos - 2);  /* fix je offset */

    sc[i++]=0x9D;                           /* popfq                (1) */
    sc[i++]=0x5B;                           /* pop rbx              (1) */

    /* stolen 15 bytes + abs JMP back 14 bytes = 29 bytes */
    for (UINT32 _k = 0; _k < PS_STOLEN_LEN; _k++) sc[i + _k] = stolen[_k];
    i += PS_STOLEN_LEN;
    UINT64 retAddr = hookVA + PS_STOLEN_LEN;
    WriteAbsJmp(&sc[i], retAddr); i += 14;

    return i; /* = 61 bytes */
}

/* ── Hook install ────────────────────────────────────────────────── */
static BOOL InstallHook(UINT64 cr3)
{
    HMODULE hLocal = GetModuleHandleA("WS2_32.dll");
    if (!hLocal) { DEBUG_PS("InstallHook: WS2_32.dll not in loader"); return FALSE; }
    UINT64 localFn  = (UINT64)GetProcAddress(hLocal, "sendto");
    if (!localFn) { DEBUG_PS("InstallHook: sendto not found"); return FALSE; }
    UINT64 fnOffset = localFn - (UINT64)hLocal;

    UINT64 peb = GetDestiny2PEB();
    if (!peb) { DEBUG_PS("InstallHook: no PEB"); return FALSE; }

    UINT64 ws2Base = BYOVD_GetModuleBase(cr3, peb, L"WS2_32.dll");
    if (!ws2Base) ws2Base = BYOVD_GetModuleBase(cr3, peb, L"WS2_32.DLL");
    if (!ws2Base) { DEBUG_PS("InstallHook: WS2_32.dll not in game"); return FALSE; }

    UINT64 hookVA = ws2Base + fnOffset;
    DEBUG_PS("InstallHook: sendto=0x%I64X", hookVA);

    /* Read PS_STOLEN_LEN+1 bytes to verify instruction boundary */
    UINT8 buf[PS_STOLEN_LEN+1] = {0};
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, hookVA, buf, sizeof(buf));
    BYOVD_UNLOCK();
    if (!ok) { DEBUG_PS("InstallHook: read failed"); return FALSE; }

    DEBUG_PS("InstallHook: bytes: %02X %02X %02X %02X %02X %02X %02X %02X "
             "%02X %02X %02X %02X %02X %02X %02X %02X",
             buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],
             buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]);

    UINT64 d2Base = (UINT64)GetDestiny2Base();

    /* Find data cave — any DLL, ≥32 bytes, skip game exe */
    UINT64 dataCave = FindCaveAnywhere(cr3, peb, PS_DATA_MIN, 0, d2Base);
    if (!dataCave) { DEBUG_PS("InstallHook: no data cave"); return FALSE; }

    /* Find code cave — any DLL, ≥64 bytes, skip game exe & data cave */
    UINT64 codeCave = FindCaveAnywhere(cr3, peb, PS_CODE_MIN, dataCave, d2Base);
    if (!codeCave) { DEBUG_PS("InstallHook: no code cave"); return FALSE; }

    /* Zero data cave (mailbox init) */
    UINT8 zeros[PS_DATA_MIN] = {0};
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, dataCave, zeros, PS_DATA_MIN);
    BYOVD_UNLOCK();

    /* Build and write shellcode to code cave */
    UINT8 sc[128] = {0};
    UINT32 scLen = BuildSC(sc, dataCave, hookVA, buf);
    DEBUG_PS("InstallHook: shellcode %u bytes (need <= %d)", scLen, PS_CODE_MIN);
    if (scLen > PS_CODE_MIN) { DEBUG_PS("InstallHook: shellcode too large!"); return FALSE; }

    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, codeCave, sc, scLen);
    BYOVD_UNLOCK();

    /* Enable mailbox */
    UINT64 flag = 1ULL;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, dataCave + PS_CAVE_ENABLED, &flag, 8);
    BYOVD_UNLOCK();

    /* Save original bytes for restoration on shutdown */
    for (UINT32 _k = 0; _k < PS_STOLEN_LEN; _k++) s_origBytes[_k] = buf[_k];

    /* Patch WSASendTo: 14-byte abs JMP to codeCave + 1-byte NOP */
    UINT8 patch[PS_STOLEN_LEN];
    WriteAbsJmp(patch, codeCave);
    patch[14] = 0x90; /* NOP — pads the 15th stolen byte */
    BYOVD_LOCK();
    BYOVD_WriteVA_Fresh(cr3, hookVA, patch, PS_STOLEN_LEN);
    BYOVD_UNLOCK();

    s_dataCaveVA = dataCave;
    s_codeCaveVA = codeCave;
    s_hookVA     = hookVA;
    DEBUG_PS("InstallHook: OK — hook live");
    return TRUE;
}

/* ── Public API ──────────────────────────────────────────────────── */
void PacketScan_Init(void)
{
    if (s_hookVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) { DEBUG_PS("Init: no CR3"); return; }
    InstallHook(cr3);
}

void PacketScan_Tick(void)
{
    if (!s_dataCaveVA || !s_hookVA) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 hitCount = 0;
    UINT64 bufVA    = 0;
    UINT32 bufLen   = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, s_dataCaveVA + PS_CAVE_HIT,    &hitCount, 8);
    BYOVD_ReadVA(cr3, s_dataCaveVA + PS_CAVE_BUFVA,  &bufVA,    8);
    BYOVD_ReadVA(cr3, s_dataCaveVA + PS_CAVE_BUFLEN, &bufLen,   4);
    BYOVD_UNLOCK();

    /* Diagnostic: log every ~5s (300 ticks) */
    static UINT64 s_diagTick = 0;
    if (++s_diagTick % 300 == 0)
        DEBUG_PS("Tick#%I64u: hitCount=%I64u buf=0x%I64X len=%u",
                 s_diagTick, hitCount, bufVA, bufLen);

    if (hitCount == s_lastHit) return;
    s_lastHit = hitCount;

    if (!bufVA || bufLen == 0 || bufLen > 4096) return;

    UINT32 readLen = bufLen < 256 ? bufLen : 256;
    UINT8  pkt[256] = {0};
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, bufVA, pkt, readLen);
    BYOVD_UNLOCK();
    if (!ok) return;

#ifndef NDEBUG
    FILE *f = fopen("packets.txt", "a");
    if (!f) return;

    fprintf(f, "\n=== PACKET #%I64u  len=%u ===\n", hitCount, bufLen);
    UINT32 row;
    for (row = 0; row < readLen; row += 16) {
        UINT32 col, end = row + 16 < readLen ? row + 16 : readLen;
        fprintf(f, "  %04X  ", row);
        for (col = row; col < end; col++)      fprintf(f, "%02X ", pkt[col]);
        for (col = end; col < row+16; col++)   fprintf(f, "   ");
        fprintf(f, " |");
        for (col = row; col < end; col++)
            fprintf(f, "%c", (pkt[col]>=0x20 && pkt[col]<0x7F) ? pkt[col] : '.');
        fprintf(f, "|\n");
    }
    fclose(f);
#endif
}

void PacketScan_Shutdown(void)
{
    if (!s_hookVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (cr3) {
        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_hookVA, s_origBytes, PS_STOLEN_LEN);
        BYOVD_UNLOCK();
    }
    s_hookVA     = 0;
    s_dataCaveVA = 0;
    s_codeCaveVA = 0;
    s_lastHit    = 0;
    DEBUG_PS("Shutdown: hook restored");
}

#endif /* SERAPH_DEV_PACKETSCAN */
