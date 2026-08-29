#ifndef SERAPH_DMA_BUILD
#ifndef NDEBUG
/* handling_speed.c — Weapon Handling Speed modifier.
 *
 * AOB (11 bytes, all exact):
 *   48 2B D8                         sub rbx, rax       (context)
 *   F3 0F 10 86 18 13 00 00          movss xmm0, [rsi+0x1318]  (Stolen instruction)
 *   80 3D F1 FF FF FF 00             cmp byte ptr [rip-15], 0   (Enabled? ip offset points to +0x00)
 *   74 08                            jz return_stock
 *   F3 0F 59 05 E3 FF FF FF          mulss xmm0, dword ptr [rip-29] (Multiply by +0x04)
 *   return_stock:
 *   FF 25 E5 FF FF FF                jmp qword ptr [rip-27]    (Jump back to hookVA + 8)
 *
 * Note on RIP-relative offsets:
 *   Enabled (+0x00):   target=0,   rip=15.  15-15 = 0.   asm=rip-15
 *   Multiplier (+0x04):target=4,   rip=33.  33-29 = 4.   asm=rip-29
 *   Jmp Target (+0x08):target=8,   rip=41.  41-27 = 14.
 */

#include "ThemidaSDK.h"
#include "handling_speed.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "cave_finder.h"
#include "lazyhook.h"
#include "attach.h"
#include "debug.h"
#include <string.h>



#define HS_AOB_OFF      3    /* hook at matchVA+3 = movss xmm0,[rsi+0x1318] */
#define HS_STOLEN_LEN   8    /* movss xmm0,[rsi+0x1318] */
#define HS_DATA_OFF     8    /* cave+0 = data, cave+8 = shellcode */
#define HS_CAVE_NEED    80
#define HS_OFF_ENABLED  0
#define HS_OFF_MULT     4

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static UINT64 s_scVA      = 0;
static int    s_hookId    = -1;
static BOOL   s_enabled   = FALSE;
static float  s_mult      = 2.0f;

void HSpeed_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL HSpeed_IsReady(void)   { return s_hookVA != 0 && s_caveVA != 0; }
BOOL HSpeed_IsEnabled(void) { return s_enabled; }

/* Shellcode: stolen inline (LOAD) → enabled gate → mulss xmm0 → jmp return.
 * The stolen is a LOAD so we must execute it before multiplying.
 * Total: 8+1+1+7+2+2+8+1+1+5 = 36 bytes. */
static int Build_Shellcode(UINT8 *cave, UINT64 cave_base, UINT64 hookVA)
{
    UINT64 sc_base   = cave_base + HS_DATA_OFF;
    UINT8 *sc        = cave + HS_DATA_OFF;
    UINT64 enabledVA = cave_base + HS_OFF_ENABLED;
    UINT64 multVA    = cave_base + HS_OFF_MULT;
    UINT64 returnVA  = hookVA + HS_STOLEN_LEN;
    int p = 0;

    /* Always execute stolen: movss xmm0, [rsi+0x1318] */
const UINT8 stolen[] = {0xF3,0x0F,0x10,0x86,0x18,0x13,0x00,0x00};

    for (int i = 0; i < 8; i++) sc[p++] = stolen[i];

    /* Preserve flags from the preceding `sub rbx, rax`.
     * movss doesn't touch flags, but our enabled-gate would. */
    sc[p++] = 0x9C; /* pushfq */

    /* push rax */
    sc[p++] = 0x50;

    /* movzx eax, byte [rip+enabledVA]   0F B6 05 disp32 */
    { UINT64 ins = sc_base + p; INT32 d = (INT32)((INT64)enabledVA - (INT64)(ins + 7));
      sc[p++]=0x0F; sc[p++]=0xB6; sc[p++]=0x05; *(INT32*)(sc+p)=d; p+=4; }

    /* test al, al */
    sc[p++]=0x84; sc[p++]=0xC0;

    /* jz skip (short) */
    int jzPos = p; sc[p++]=0x74; sc[p++]=0x00;

    /* mulss xmm0, dword [rip+multVA]   F3 0F 59 05 disp32 */
    { UINT64 ins = sc_base + p; INT32 d = (INT32)((INT64)multVA - (INT64)(ins + 8));
      sc[p++]=0xF3; sc[p++]=0x0F; sc[p++]=0x59; sc[p++]=0x05;
      *(INT32*)(sc+p)=d; p+=4; }

    /* skip: patch jz delta */
    sc[jzPos+1] = (UINT8)(p - (jzPos + 2));

    /* pop rax */
    sc[p++] = 0x58;

    /* Restore flags */
    sc[p++] = 0x9D; /* popfq */

    /* jmp returnVA — always, skipping LazyHook's appended stolen+jmpback */
    { UINT64 ins = sc_base + p; INT32 d = (INT32)((INT64)returnVA - (INT64)(ins + 5));
      sc[p++]=0xE9; *(INT32*)(sc+p)=d; p+=4; }

    return p;
}

#include "xor_strings.h"

#pragma optimize("", off)
void HSpeed_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("HSpeed: A enter");
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("HSpeed: B no cr3/base"); goto _hs_end; }

    UINT64 matchVA = d2Base + SecureReadStatic(&OBF_OFF_HSpeed);
    { char b[80]; wsprintfA(b,"HSpeed: D matchVA=0x%I64X (Secure)",matchVA); WriteLogFile(b); }
    if (!matchVA) { WriteLogFile("HSpeed: E AOB NOT FOUND"); goto _hs_end; }

    s_hookVA = matchVA + HS_AOB_OFF;
    { char b[80]; wsprintfA(b,"HSpeed: F hookVA=0x%I64X",s_hookVA); WriteLogFile(b); }

    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, HS_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    if (!s_caveVA) { WriteLogFile("HSpeed: G cave not found"); s_hookVA=0; goto _hs_end; }

    s_scVA = s_caveVA + HS_DATA_OFF;
    WriteLogFile("HSpeed: Z OK");
_hs_end:
    MUTATE_END
}
#pragma optimize("", on)

void HSpeed_SetMultiplier(float mult)
{
    if (mult < 1.0f) mult = 1.0f;
    if (mult > 10.0f) mult = 10.0f;
    s_mult = mult;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_caveVA + HS_OFF_MULT, &s_mult, 4);
    BYOVD_UNLOCK();
}

void HSpeed_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !HSpeed_IsReady()) return;
    s_enabled = state;

    if (state) {
        if (s_hookId != -1) return;

        UINT8 cave[HS_CAVE_NEED]; memset(cave, 0, sizeof(cave));
        cave[HS_OFF_ENABLED] = 1;
        *(float*)(cave + HS_OFF_MULT) = s_mult;

        int scLen = Build_Shellcode(cave, s_caveVA, s_hookVA);

        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA, cave, HS_DATA_OFF);
        BYOVD_UNLOCK();

        s_hookId = LazyHook_Install(cr3, s_hookVA, HS_STOLEN_LEN,
                                    cave + HS_DATA_OFF, (UINT32)scLen, s_scVA);
        if (s_hookId == -1) s_enabled = FALSE;
    } else {
        if (s_hookId != -1) { LazyHook_Remove(s_hookId, cr3); s_hookId = -1; }
        UINT8 zero = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA + HS_OFF_ENABLED, &zero, 1);
        BYOVD_UNLOCK();
    }
}

#pragma optimize("", off)
void HSpeed_OnDetach(void)
{
    MUTATE_START
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId != -1 && cr3) LazyHook_Remove(s_hookId, cr3);
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;
    MUTATE_END
}
#pragma optimize("", on)
#endif
#endif

