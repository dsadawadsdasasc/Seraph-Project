
#include "ThemidaSDK.h"
#include "immune_boss.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"
#include <string.h>

/* Immune Bosses — lazyhook on F3 0F 10 44 86 48 (movss xmm0,[rsi+rax*4+0x48]).
 *
 * Filter 1: [r15]  == 1.0f      — only immunity slots pass
 * Filter 2: rsi    >= 0x10000   — sanity check, avoids crash on boss death
 * Filter 3: [rsi+3] != 0x43    — skips "bad" slots that share the same float
 *
 * Cave shellcode (45 bytes):
 *   00  50                         push rax
 *   01  41 57                      push r15
 *   03  4C 8D 7C 86 48             lea r15,[rsi+rax*4+0x48]
 *   08  41 8B 07                   mov eax,[r15]
 *   0B  3D 00 00 80 3F             cmp eax,0x3F800000    ==1.0f?
 *   10  75 18                      jne skip -> 2A
 *   12  48 81 FE 00 00 01 00       cmp rsi,0x10000
 *   19  72 0F                      jb  skip -> 2A
 *   1B  0F B6 46 03                movzx eax,byte[rsi+3]
 *   1F  3C 43                      cmp al,0x43
 *   21  74 07                      je  skip -> 2A
 *   23  41 C7 07 00 00 00 00       mov dword[r15],0
 *   2A  41 5F                      pop r15  ; skip:
 *   2C  58                         pop rax
 */








#define IB_AOB_LEN    6
#define IB_STOLEN_LEN 6
#define IB_SHELL_LEN  46
#define IB_CAVE_NEED  (IB_SHELL_LEN + IB_STOLEN_LEN + 5)

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static int    s_hookId    = -1;
static BOOL   s_ready     = FALSE;
static BOOL   s_enabled   = FALSE;

void ImmuneBoss_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL ImmuneBoss_IsReady(void)   { return s_ready; }
BOOL ImmuneBoss_IsEnabled(void) { return s_enabled; }
void ImmuneBoss_Tick(void)      { (void)0; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void ImmuneBoss_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_caveVA = 0; s_hookId = -1;
    s_ready = FALSE; s_enabled = FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2  = GetDestiny2Base();
    if (!cr3 || !d2) goto _end;

    UINT64 va = s_preScanVA;
    if (!va) {
        BYOVD_LOCK();
        va = BYOVD_ScanPatternText(cr3, d2, k_ib_pat, k_ib_mask, 6);
        BYOVD_UNLOCK();
    }
    if (!va) goto _end;
    s_hookVA = va;


    BYOVD_LOCK();
    UINT64 cave = CaveFinder_FindNear(cr3, d2, IB_CAVE_NEED, va);
    BYOVD_UNLOCK();
    if (!cave) { WriteLogFile("ImmuneBoss: no cave found"); goto _end; }
    s_caveVA = cave;

    s_ready = TRUE;
    {
        char b[160];
        wsprintfA(b, "ImmuneBoss: ready hookVA=0x%I64X (RVA=0x%I64X) caveVA=0x%I64X",
                  s_hookVA, s_hookVA - d2, s_caveVA);
        WriteLogFile(b);
    }
_end:
    MUTATE_END
}
#pragma optimize("", on)

void ImmuneBoss_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    s_enabled = state;

    if (!s_ready) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    if (state) {
        if (s_hookId != -1) return;
        /* Updated shellcode (46 bytes):
         * Doesn't write to memory. Instead, zeroes xmm0 and skips the stolen bytes
         * so the game reads 0 for the immune boss, but memory stays 1.0f. */
        UINT8 sc[IB_SHELL_LEN] = {
            /* 00 */ 0x50,                                      /* push rax                      */
            /* 01 */ 0x41, 0x57,                                /* push r15                      */
            /* 03 */ 0x4C, 0x8D, 0x7C, 0x86, 0x48,             /* lea r15,[rsi+rax*4+0x48]      */
            /* 08 */ 0x41, 0x8B, 0x07,                          /* mov eax,[r15]                 */
            /* 0B */ 0x3D, 0x00, 0x00, 0x80, 0x3F,              /* cmp eax,0x3F800000    ==1.0f  */
            /* 10 */ 0x75, 0x19,                                /* jne skip (+0x19 -> 0x2B)      */
            /* 12 */ 0x48, 0x81, 0xFE, 0x00, 0x00, 0x01, 0x00, /* cmp rsi,0x10000               */
            /* 19 */ 0x72, 0x10,                                /* jb  skip (+0x10 -> 0x2B)      */
            /* 1B */ 0x0F, 0xB6, 0x46, 0x03,                    /* movzx eax,byte[rsi+3]         */
            /* 1F */ 0x3C, 0x43,                                /* cmp al,0x43                   */
            /* 21 */ 0x74, 0x08,                                /* je  skip (+0x08 -> 0x2B)      */
            /* 23 */ 0x0F, 0x57, 0xC0,                          /* xorps xmm0, xmm0              */
            /* 26 */ 0x41, 0x5F,                                /* pop r15                       */
            /* 28 */ 0x58,                                      /* pop rax                       */
            /* 29 */ 0xEB, 0x09,                                /* jmp short +0x09 (0x34)        */
            /* 2B */ 0x41, 0x5F,                                /* pop r15  ; skip:              */
            /* 2D */ 0x58,                                      /* pop rax                       */
        };
        s_hookId = LazyHook_Install(cr3, s_hookVA, IB_STOLEN_LEN,
                                    sc, IB_SHELL_LEN, s_caveVA);
        char b[160];
        wsprintfA(b, "ImmuneBoss ENABLE: hookId=%d hookVA=0x%I64X caveVA=0x%I64X",
                  s_hookId, s_hookVA, s_caveVA);
        WriteLogFile(b);
    } else {
        if (s_hookId == -1) return;
        BOOL ok = LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
        char b[80];
        wsprintfA(b, "ImmuneBoss DISABLE: remove=%d", ok ? 1 : 0);
        WriteLogFile(b);
    }
}

#pragma optimize("", off)
void ImmuneBoss_OnDetach(void)
{
    MUTATE_START
    if (s_hookId != -1) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
    }
    s_hookVA = 0; s_caveVA = 0;
    s_ready = FALSE; s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

