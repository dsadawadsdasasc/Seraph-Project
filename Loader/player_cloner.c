
#include "ThemidaSDK.h"
#include "player_cloner.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"
#include <string.h>

/* Player Cloner — CE script port.
 *
 * AOB: 0F 29 85 ? ? ? ? ? ? ? 44 0F 28 BD ? ? ? ? E9 ? ? ? ? 0F B6 47
 * Hook at matchVA+0, stolen 7 bytes: movaps [rbp+disp32], xmm0.
 *
 * Logic: if xmm0 scalar in [-1.0, -0.99] → replace xmm0 with {1,1,-1,1}.
 * In all cases the stolen instruction (movaps [rbp+disp32], xmm0) is then
 * executed via the LazyHook fallthrough (stolen bytes appended after shellcode).
 *
 * Cave layout:
 *   +0x00  float min_threshold  (-1.0f)
 *   +0x04  float max_threshold  (-0.99f)
 *   +0x08  float xmm0_all[4]   {1.0, 1.0, -1.0, 1.0}  (16 bytes)
 *   +0x18  uint8 enabled
 *   +0x19..0x1F  padding
 *   +0x20  shellcode
 */








#define CLONER_AOB_OFF     0
#define CLONER_STOLEN_LEN  7
#define CLONER_OFF_MIN     0x00
#define CLONER_OFF_MAX     0x04
#define CLONER_OFF_XMM0    0x08
#define CLONER_OFF_ENABLED 0x18
#define CLONER_DATA_OFF    0x20
#define CLONER_CAVE_NEED   128

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static UINT64 s_scVA      = 0;
static int    s_hookId    = -1;
static BOOL   s_enabled   = FALSE;

void PlayerCloner_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

/* Shellcode:
 *   ucomiss xmm0, [rip+min]  → jp/jb skip_mod  (out of range low)
 *   ucomiss xmm0, [rip+max]  → jp/ja skip_mod  (out of range high)
 *   movups  xmm0, [rip+xmm0_all]               ← apply mod
 *   skip_mod: (LazyHook appends stolen + jmp back)
 *
 * NOTE: ucomiss xmm0, [mem] does NOT modify xmm0, so we compare the
 * original value directly without needing xmm1/xmm2 as temporaries.
 * This is critical: xmm1/xmm2 are live in D2's code at this hook site
 * and clobbering them caused the crash in the previous implementation.
 */
static int Build_Shellcode(UINT8 *cave, UINT64 cave_base, UINT64 hookVA)
{
    (void)hookVA;
    UINT64 sc_base   = cave_base + CLONER_DATA_OFF;
    UINT8 *sc        = cave + CLONER_DATA_OFF;
    UINT64 minVA     = cave_base + CLONER_OFF_MIN;
    UINT64 maxVA     = cave_base + CLONER_OFF_MAX;
    UINT64 xmm0VA    = cave_base + CLONER_OFF_XMM0;
    int p = 0;

    /* ucomiss xmm0, [rip+min] — 0F 2E 05 disp32 (7 bytes, RIP=ins+7)
     * Compares xmm0 scalar against min threshold WITHOUT modifying xmm0. */
    { UINT64 ins=sc_base+p; INT32 d=(INT32)((INT64)minVA-(INT64)(ins+7));
      sc[p++]=0x0F; sc[p++]=0x2E; sc[p++]=0x05; *(INT32*)(sc+p)=d; p+=4; }

    int jp1Pos=p; sc[p++]=0x7A; sc[p++]=0x00;  /* jp  skip_mod (NaN/unordered) */
    int jbPos=p;  sc[p++]=0x72; sc[p++]=0x00;  /* jb  skip_mod (xmm0 < min)    */

    /* ucomiss xmm0, [rip+max] — 0F 2E 05 disp32 (7 bytes, RIP=ins+7)
     * Compares xmm0 scalar against max threshold. Still no register clobber. */
    { UINT64 ins=sc_base+p; INT32 d=(INT32)((INT64)maxVA-(INT64)(ins+7));
      sc[p++]=0x0F; sc[p++]=0x2E; sc[p++]=0x05; *(INT32*)(sc+p)=d; p+=4; }

    int jp2Pos=p; sc[p++]=0x7A; sc[p++]=0x00;  /* jp  skip_mod (NaN/unordered) */
    int jaPos=p;  sc[p++]=0x77; sc[p++]=0x00;  /* ja  skip_mod (xmm0 > max)    */

    /* movups xmm0, [rip+xmm0_all] — 0F 10 05 disp32 (7 bytes, RIP=ins+7) */
    { UINT64 ins=sc_base+p; INT32 d=(INT32)((INT64)xmm0VA-(INT64)(ins+7));
      sc[p++]=0x0F; sc[p++]=0x10; sc[p++]=0x05; *(INT32*)(sc+p)=d; p+=4; }

    /* patch all forward jumps to skip_mod */
    sc[jp1Pos+1]=(UINT8)(p-(jp1Pos+2));
    sc[jbPos+1] =(UINT8)(p-(jbPos+2));
    sc[jp2Pos+1]=(UINT8)(p-(jp2Pos+2));
    sc[jaPos+1] =(UINT8)(p-(jaPos+2));

    return p;
}

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void PlayerCloner_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("Cloner: A enter");
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("Cloner: B no cr3/base"); goto _cloner_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_cloner_pat, k_cloner_mask, CLONER_AOB_LEN);
        BYOVD_UNLOCK();
    }
    { char b[80]; wsprintfA(b,"Cloner: D matchVA=0x%I64X",matchVA); WriteLogFile(b); }
    if (!matchVA) { WriteLogFile("Cloner: E AOB NOT FOUND"); goto _cloner_end; }


    s_hookVA = matchVA + CLONER_AOB_OFF;

    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, CLONER_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    { char b[80]; wsprintfA(b,"Cloner: F caveVA=0x%I64X",s_caveVA); WriteLogFile(b); }
    if (!s_caveVA) { WriteLogFile("Cloner: G cave not found"); s_hookVA=0; goto _cloner_end; }

    s_scVA = s_caveVA + CLONER_DATA_OFF;
    WriteLogFile("Cloner: Z OK");
_cloner_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL PlayerCloner_IsReady(void)   { return s_hookVA != 0 && s_caveVA != 0; }
BOOL PlayerCloner_IsEnabled(void) { return s_enabled; }

void PlayerCloner_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !PlayerCloner_IsReady()) return;
    s_enabled = state;

    if (state) {
        if (s_hookId != -1) return;

        UINT8 cave[CLONER_CAVE_NEED]; memset(cave, 0, sizeof(cave));
        *(float*)(cave + CLONER_OFF_MIN)      = -1.0f;
        *(float*)(cave + CLONER_OFF_MAX)      = -0.99f;
        *(float*)(cave + CLONER_OFF_XMM0+0)  =  1.0f;
        *(float*)(cave + CLONER_OFF_XMM0+4)  =  1.0f;
        *(float*)(cave + CLONER_OFF_XMM0+8)  = -1.0f;
        *(float*)(cave + CLONER_OFF_XMM0+12) =  1.0f;
        cave[CLONER_OFF_ENABLED] = 1;

        int scLen = Build_Shellcode(cave, s_caveVA, s_hookVA);

        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA, cave, CLONER_DATA_OFF);
        BYOVD_UNLOCK();

        s_hookId = LazyHook_Install(cr3, s_hookVA, CLONER_STOLEN_LEN,
                                    cave + CLONER_DATA_OFF, (UINT32)scLen, s_scVA);
        if (s_hookId == -1) s_enabled = FALSE;
    } else {
        if (s_hookId != -1) { LazyHook_Remove(s_hookId, cr3); s_hookId = -1; }
        UINT8 zero = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA + CLONER_OFF_ENABLED, &zero, 1);
        BYOVD_UNLOCK();
    }
}

#pragma optimize("", off)
void PlayerCloner_OnDetach(void)
{
    MUTATE_START
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId != -1 && cr3) LazyHook_Remove(s_hookId, cr3);
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;
    MUTATE_END
}
#pragma optimize("", on)

