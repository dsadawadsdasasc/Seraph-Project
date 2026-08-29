
#include "ThemidaSDK.h"
#include "xor_strings.h"
#include "interact_aura.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"
#include <string.h>

/* Interact Aura — lazyhook at "8B 54 01 6C 8B 4F 24 8B C1 C1 F8 0D"
 *
 * Hook point (from CE): 7FF67A6F1A8D
 *   8B 54 01 6C   mov edx,[rcx+rax+6C]  <- interact range read
 *   8B 4F 24      mov ecx,[rdi+24]      <- interact data read
 *   8B C1         mov eax,ecx
 *   C1 F8 0D      sar eax,0D
 *
 * Stolen (7 bytes): 8B 54 01 6C 8B 4F 24
 *
 * Cave layout (ITAR_CAVE_NEED bytes):
 *   [datVA+0]   : toggle byte  (0 = restore mode, 1 = active)
 *   [datVA+1-4] : savedRange   (float, 0 = not yet captured)
 *   [datVA+5-8] : savedTime    (float)
 *   [datVA+9..] : shellcode written by LazyHook_Install
 *
 * Shellcode (103 bytes, at datVA+9):
 *   Saves original values on first active call.
 *   toggle=1: writes 100000.0f to [rcx+rax+6C] and 0.0f to [rcx+rax+74].
 *   toggle=0: writes saved originals back (immediate restore on disable).
 *
 * float 100000.0f = 0x47C35000 (LE: 00 50 C3 47)
 * float 0.0f      = 0x00000000
 *
 * Jump offsets (relative to next instr):
 *   off16 jne +0x22 → off52 (enable path)
 *   off22 je  +0x4C → off100 (done)
 *   off50 jmp +0x30 → off100 (done)
 *   off66 jne +0x10 → off84  (write_values)
 */








#define ITAR_AOB_LEN    12
#define ITAR_STOLEN_LEN  7
#define ITAR_SHELL_LEN  103
#define ITAR_DATA_LEN    9
#define ITAR_CAVE_NEED  (ITAR_DATA_LEN + ITAR_SHELL_LEN + ITAR_STOLEN_LEN + 5)

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_datVA     = 0;
static int    s_hookId    = -1;
static BOOL   s_ready     = FALSE;
static BOOL   s_enabled   = FALSE;

void InteractAura_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL InteractAura_IsReady(void)   { return s_ready; }
BOOL InteractAura_IsEnabled(void) { return s_enabled; }
void InteractAura_Tick(void)      { (void)0; }

#include "aob_patterns.h"

#pragma optimize("", off)
void InteractAura_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_datVA = 0; s_hookId = -1;
    s_ready = FALSE; s_enabled = FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2  = GetDestiny2Base();
    if (!cr3 || !d2) goto _end;

    UINT64 va = s_preScanVA;
    if (!va) {
        BYOVD_LOCK();
        va = BYOVD_ScanPatternText(cr3, d2, k_itar_pat, k_itar_mask, 12);
        BYOVD_UNLOCK();
    }
    if (!va) { WriteLogFile("InteractAura: AOB match is NULL"); goto _end; }
    s_hookVA = va;


    BYOVD_LOCK();
    UINT64 cave = CaveFinder_FindNear(cr3, d2, ITAR_CAVE_NEED, va);
    BYOVD_UNLOCK();
    if (!cave) { WriteLogFile("InteractAura: no cave found"); goto _end; }
    s_datVA = cave;

    /* Zero the data prefix: toggle=0, savedRange=0, savedTime=0.
     * Use _Fresh to bypass the VAPA cache — if this is a re-attach the
     * previous session's shellcode may have triggered Windows COW on this
     * .text cave page, making any cached PA stale. */
    {
        UINT8 z[ITAR_DATA_LEN] = {0};
        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_datVA, z, ITAR_DATA_LEN);
        BYOVD_UNLOCK();
    }

    s_ready = TRUE;
    {
        char b[160];
        wsprintfA(b, "InteractAura: ready hookVA=0x%I64X (RVA=0x%I64X) datVA=0x%I64X",
                  s_hookVA, s_hookVA - d2, s_datVA);
        WriteLogFile(b);
    }
_end:
    MUTATE_END
}
#pragma optimize("", on)

void InteractAura_SetEnabled(BOOL state)
{
    if (s_enabled == (state ? TRUE : FALSE)) return;

    if (!s_ready) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    s_enabled = state ? TRUE : FALSE;

    if (state) {
        /* First enable: install hook */
        if (s_hookId == -1) {
            UINT8 sc[ITAR_SHELL_LEN];
            UINT64 dv = s_datVA;
            UINT8  dv8[8]; memcpy(dv8, &dv, 8);

            /* === Shellcode (103 bytes) ===
             * Stack after push rax/rcx/rbx:
             *   [rsp+ 0] = saved rbx
             *   [rsp+ 8] = saved rcx (orig object ptr)
             *   [rsp+16] = saved rax (orig byte offset)
             */
            /* off  0 */ sc[0]=0x50;
            /* off  1 */ sc[1]=0x51;
            /* off  2 */ sc[2]=0x53;
            /* off  3 */ sc[3]=0x48;sc[4]=0xBB;                           /* mov rbx, datVA */
                         sc[5]=dv8[0];sc[6]=dv8[1];sc[7]=dv8[2];sc[8]=dv8[3];
                         sc[9]=dv8[4];sc[10]=dv8[5];sc[11]=dv8[6];sc[12]=dv8[7];
            /* off 13 */ sc[13]=0x80;sc[14]=0x3B;sc[15]=0x00;             /* cmp byte[rbx],0 */
            /* off 16 */ sc[16]=0x75;sc[17]=0x22;                         /* jne +34 -> off52 (enable path) */
            /* off 18 */ sc[18]=0x83;sc[19]=0x7B;sc[20]=0x01;sc[21]=0x00; /* cmp dword[rbx+1],0 */
            /* off 22 */ sc[22]=0x74;sc[23]=0x4C;                         /* je  +76 -> off100 (done) */
            /* off 24 */ sc[24]=0x48;sc[25]=0x8B;sc[26]=0x44;sc[27]=0x24;sc[28]=0x10; /* mov rax,[rsp+16] */
            /* off 29 */ sc[29]=0x48;sc[30]=0x8B;sc[31]=0x4C;sc[32]=0x24;sc[33]=0x08; /* mov rcx,[rsp+8]  */
            /* off 34 */ sc[34]=0x57;                                      /* push rdi */
            /* off 35 */ sc[35]=0x8B;sc[36]=0x7B;sc[37]=0x01;             /* mov edi,[rbx+1]     -- savedRange */
            /* off 38 */ sc[38]=0x89;sc[39]=0x7C;sc[40]=0x01;sc[41]=0x6C; /* mov [rcx+rax+6C],edi */
            /* off 42 */ sc[42]=0x8B;sc[43]=0x7B;sc[44]=0x05;             /* mov edi,[rbx+5]     -- savedTime  */
            /* off 45 */ sc[45]=0x89;sc[46]=0x7C;sc[47]=0x01;sc[48]=0x74; /* mov [rcx+rax+74],edi */
            /* off 49 */ sc[49]=0x5F;                                      /* pop rdi */
            /* off 50 */ sc[50]=0xEB;sc[51]=0x30;                         /* jmp +48 -> off100 (done) */
            /* off 52 */ sc[52]=0x48;sc[53]=0x8B;sc[54]=0x44;sc[55]=0x24;sc[56]=0x10; /* mov rax,[rsp+16] */
            /* off 57 */ sc[57]=0x48;sc[58]=0x8B;sc[59]=0x4C;sc[60]=0x24;sc[61]=0x08; /* mov rcx,[rsp+8]  */
            /* off 62 */ sc[62]=0x83;sc[63]=0x7B;sc[64]=0x01;sc[65]=0x00; /* cmp dword[rbx+1],0 (first call?) */
            /* off 66 */ sc[66]=0x75;sc[67]=0x10;                         /* jne +16 -> off84 (write_values) */
            /* off 68 */ sc[68]=0x57;                                      /* push rdi */
            /* off 69 */ sc[69]=0x8B;sc[70]=0x7C;sc[71]=0x01;sc[72]=0x6C; /* mov edi,[rcx+rax+6C] -- save range */
            /* off 73 */ sc[73]=0x89;sc[74]=0x7B;sc[75]=0x01;             /* mov [rbx+1],edi */
            /* off 76 */ sc[76]=0x8B;sc[77]=0x7C;sc[78]=0x01;sc[79]=0x74; /* mov edi,[rcx+rax+74] -- save time  */
            /* off 80 */ sc[80]=0x89;sc[81]=0x7B;sc[82]=0x05;             /* mov [rbx+5],edi */
            /* off 83 */ sc[83]=0x5F;                                      /* pop rdi */
            /* off 84 */ sc[84]=0xC7;sc[85]=0x44;sc[86]=0x01;sc[87]=0x6C; /* mov [rcx+rax+6C], 100000.0f */
                         sc[88]=0x00;sc[89]=0x50;sc[90]=0xC3;sc[91]=0x47; /* LE: 0x47C35000 */
            /* off 92 */ sc[92]=0xC7;sc[93]=0x44;sc[94]=0x01;sc[95]=0x74; /* mov [rcx+rax+74], 0.0f */
                         sc[96]=0x00;sc[97]=0x00;sc[98]=0x00;sc[99]=0x00;
            /* off100 */ sc[100]=0x5B;                                     /* pop rbx */
            /* off101 */ sc[101]=0x59;                                     /* pop rcx */
            /* off102 */ sc[102]=0x58;                                     /* pop rax */

            s_hookId = LazyHook_Install(cr3, s_hookVA, ITAR_STOLEN_LEN,
                                        sc, ITAR_SHELL_LEN,
                                        s_datVA + ITAR_DATA_LEN);
        }

        /* Activate: set toggle byte = 1.
         * Use _Fresh: the shellcode may have already triggered COW on this
         * .text page (on a previous enable), making the VAPA-cached PA stale. */
        UINT8 tog = 1;
        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_datVA, &tog, 1);
        BYOVD_UNLOCK();

        char b[160];
        wsprintfA(b, "InteractAura ENABLE: hookId=%d hookVA=0x%I64X datVA=0x%I64X",
                  s_hookId, s_hookVA, s_datVA);
        WriteLogFile(b);
    } else {
        /* Deactivate: set toggle byte = 0.
         * Shellcode detects toggle=0 and writes back saved original values
         * on every subsequent call, restoring interact range/time naturally.
         * Use _Fresh: COW will have already occurred after first enable fired,
         * so the VAPA cache holds the stale shared-page PA — _Fresh walks
         * the current PTEs and reaches the private COW'd page D2 actually reads. */
        UINT8 tog = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA_Fresh(cr3, s_datVA, &tog, 1);
        BYOVD_UNLOCK();
        WriteLogFile("InteractAura DISABLE: toggle=0 (shellcode will restore original values)");
    }
}

#pragma optimize("", off)
void InteractAura_OnDetach(void)
{
    MUTATE_START
    if (s_hookId != -1) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
        s_hookId = -1;
    }
    s_hookVA = 0; s_datVA = 0;
    s_ready = FALSE; s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

