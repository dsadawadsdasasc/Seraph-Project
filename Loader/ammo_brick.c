
#include "ThemidaSDK.h"
#include "ammo_brick.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"
#include <string.h>

/* Ammo Brick Spawner — forces float 100.0 (0x42C60000) into [rsi+0x1C0]
 * on every execution of the movss write, keeping the ammo brick at max.
 *
 * CE script port:
 *   AOB: F3 44 0F 11 86 C0 01 00 00 0F 28 85  (hook at offset 0)
 *   Stolen 9 bytes: movss [rsi+0x1C0], xmm8
 *   When enabled: run stolen, then overwrite [rsi+0x1C0] = 42C60000 (100.0f)
 *
 * Cave layout:
 *   +0x00  uint8   enabled flag
 *   +0x01..0x07  padding
 *   +0x08  shellcode
 */








#define BRICK_AOB_OFF       0   /* hookVA = matchVA + 0 */
#define BRICK_STOLEN_LEN    9   /* movss [rsi+0x1C0], xmm8 */
#define BRICK_DATA_OFF      8   /* shellcode starts at cave+8 */
#define BRICK_CAVE_NEED    80
#define BRICK_OFF_ENABLED   0

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static UINT64 s_scVA      = 0;
static int    s_hookId    = -1;
static BOOL   s_enabled   = FALSE;

void AmmoBrick_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

/* Shellcode layout:
 *   movss [rsi+0x1C0], xmm8       (stolen, executed always)
 *   push rax
 *   movzx eax, byte [rip+enabled]
 *   test al, al
 *   pop rax
 *   jz skip
 *   mov dword ptr [rsi+0x1C0], 0x42C60000   (force 100.0f)
 * skip:
 *   jmp returnVA
 */
static int Build_Shellcode(UINT8 *cave, UINT64 cave_base, UINT64 hookVA)
{
    UINT64 sc_base   = cave_base + BRICK_DATA_OFF;
    UINT8 *sc        = cave + BRICK_DATA_OFF;
    UINT64 enabledVA = cave_base + BRICK_OFF_ENABLED;
    UINT64 returnVA  = hookVA + BRICK_STOLEN_LEN;
    int p = 0;

    /* Execute original instruction inline (always) */
const UINT8 stolen[] = {0xF3,0x44,0x0F,0x11,0x86,0xC0,0x01,0x00,0x00};

    for (int i = 0; i < (int)sizeof(stolen); i++) sc[p++] = stolen[i];

    /* push rax */
    sc[p++] = 0x50;

    /* movzx eax, byte [rip+enabledVA]  —  0F B6 05 disp32 */
    { UINT64 ins = sc_base + p; INT32 d = (INT32)((INT64)enabledVA - (INT64)(ins + 7));
      sc[p++]=0x0F; sc[p++]=0xB6; sc[p++]=0x05; *(INT32*)(sc+p)=d; p+=4; }

    /* test al, al */
    sc[p++]=0x84; sc[p++]=0xC0;

    /* pop rax  (ZF preserved across pop) */
    sc[p++]=0x58;

    /* jz skip (short) */
    int jzPos = p; sc[p++]=0x74; sc[p++]=0x00;

    /* mov dword ptr [rsi+0x1C0], 0x42C60000
     * Encoding: C7 /0  ModRM=86 (mod=10,reg=000,rm=110=rsi)  disp32=C0010000  imm32=000042C6 
     * Wait — 0x42C60000 in little-endian bytes: 00 00 C6 42 */
    sc[p++]=0xC7; sc[p++]=0x86;
    sc[p++]=0xC0; sc[p++]=0x01; sc[p++]=0x00; sc[p++]=0x00; /* disp32 = 0x000001C0 */
    sc[p++]=0x00; sc[p++]=0x00; sc[p++]=0xC6; sc[p++]=0x42; /* imm32  = 0x42C60000 */

    /* patch jz delta */
    sc[jzPos+1] = (UINT8)(p - (jzPos + 2));

    /* jmp returnVA  —  E9 disp32 */
    { UINT64 ins = sc_base + p; INT32 d = (INT32)((INT64)returnVA - (INT64)(ins + 5));
      sc[p++]=0xE9; *(INT32*)(sc+p)=d; p+=4; }

    return p;
}

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void AmmoBrick_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("Brick: A enter");
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("Brick: B no cr3/base"); goto _brick_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_brick_pat, k_brick_mask, 12);
        BYOVD_UNLOCK();
    }
    { char b[80]; wsprintfA(b,"Brick: D matchVA=0x%I64X",matchVA); WriteLogFile(b); }
    if (!matchVA) { WriteLogFile("Brick: E AOB NOT FOUND"); goto _brick_end; }


    s_hookVA = matchVA + BRICK_AOB_OFF;
    { char b[80]; wsprintfA(b,"Brick: F hookVA=0x%I64X",s_hookVA); WriteLogFile(b); }

    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, BRICK_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    { char b[80]; wsprintfA(b,"Brick: G caveVA=0x%I64X",s_caveVA); WriteLogFile(b); }
    if (!s_caveVA) { WriteLogFile("Brick: H cave not found"); s_hookVA=0; goto _brick_end; }

    s_scVA = s_caveVA + BRICK_DATA_OFF;
    WriteLogFile("Brick: Z OK");
_brick_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL AmmoBrick_IsReady(void)   { return s_hookVA != 0 && s_caveVA != 0; }
BOOL AmmoBrick_IsEnabled(void) { return s_enabled; }

void AmmoBrick_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !AmmoBrick_IsReady()) return;
    s_enabled = state;

    if (state) {
        if (s_hookId != -1) return;

        UINT8 cave[BRICK_CAVE_NEED]; memset(cave, 0, sizeof(cave));
        cave[BRICK_OFF_ENABLED] = 1;

        int scLen = Build_Shellcode(cave, s_caveVA, s_hookVA);

        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA, cave, BRICK_DATA_OFF);
        BYOVD_UNLOCK();

        s_hookId = LazyHook_Install(cr3, s_hookVA, BRICK_STOLEN_LEN,
                                    cave + BRICK_DATA_OFF, (UINT32)scLen, s_scVA);
        if (s_hookId == -1) s_enabled = FALSE;
    } else {
        if (s_hookId != -1) { LazyHook_Remove(s_hookId, cr3); s_hookId = -1; }
        UINT8 zero = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA + BRICK_OFF_ENABLED, &zero, 1);
        BYOVD_UNLOCK();
    }
}

#pragma optimize("", off)
void AmmoBrick_OnDetach(void)
{
    MUTATE_START
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId != -1 && cr3) LazyHook_Remove(s_hookId, cr3);
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;
    MUTATE_END
}
#pragma optimize("", on)

