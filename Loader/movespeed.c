
/* movespeed.c — Movement Speed modifier.
 *
 * Based on CE script:
 *   AOB: F3 0F ?? ?? ?? ?? ?? ?? 44 0F B6 CE 0F 28 F7
 *   Hook: replace movss xmm7,[rip+...] with movss xmm7,[aura]
 *   aura = float value 1.0..10.0 controlling movement speed
 *
 * The stolen instruction is: movss xmm7, [rip+disp32]  (8 bytes, F3 0F 10 3D ..)
 * CE original bytes: F3 0F 10 3D DA B7 A0 01
 * Shellcode replaces the load: movss xmm7, [cave+MS_OFF_VALUE]
 *
 * Cave layout:
 *   +0x00  uint8  enabled
 *   +0x01..0x03  padding
 *   +0x04  float  value   (default 5.0f = default game speed)
 *   +0x08  shellcode
 */

#include "ThemidaSDK.h"
#include "movespeed.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include <string.h>

/* AOB: F3 0F ?? ?? ?? ?? ?? ?? 44 0F B6 CE 0F 28 F7
 * The first 8 bytes are the stolen movss xmm7,[rip+disp32].
 * Wildcards on bytes 2-7 (opcode fields / displacement). */







#define MS_AOB_OFF      0    /* hook at match start (the movss xmm7 itself) */
#define MS_STOLEN_LEN   8    /* movss xmm7,[rip+disp32] = 8 bytes */
#define MS_DATA_OFF     8    /* cave+0..7 = data, cave+8 = shellcode */
#define MS_CAVE_NEED    80
#define MS_OFF_ENABLED  0
#define MS_OFF_VALUE    4

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA    = 0;
static UINT64 s_caveVA    = 0;
static UINT64 s_scVA      = 0;
static int    s_hookId    = -1;
static BOOL   s_enabled   = FALSE;
static float  s_value     = 5.0f;  /* default = game's default speed */

void MSpeed_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL MSpeed_IsReady(void)   { return s_hookVA != 0 && s_caveVA != 0; }
BOOL MSpeed_IsEnabled(void) { return s_enabled; }

/* Shellcode (simplified, matching CE script):
 *   movss xmm7, dword [rip+valueVA]    <- load our speed value
 *   jmp returnVA
 *
 * This is much simpler than the original — no enabled gate, no stolen bytes.
 * The hook is always active; enable/disable is handled by toggling the hook itself.
 */
static int Build_Shellcode(UINT8 *cave, UINT64 cave_base, UINT64 hookVA)
{
    UINT64 sc_base   = cave_base + MS_DATA_OFF;
    UINT8 *sc        = cave + MS_DATA_OFF;
    UINT64 valueVA   = cave_base + MS_OFF_VALUE;
    UINT64 returnVA  = hookVA + MS_STOLEN_LEN;
    int p = 0;

    /* Build: movss xmm7, dword [rip+valueVA]
     * F3 0F 10 3D disp32 (8 bytes) */
    {
        UINT64 ins = sc_base + p;
        INT32 d = (INT32)((INT64)valueVA - (INT64)(ins + 8));
        sc[p++] = 0xF3;
        sc[p++] = 0x0F;
        sc[p++] = 0x10;
        sc[p++] = 0x3D;  /* ModR/M for xmm7 */
        *(INT32*)(sc + p) = d;
        p += 4;
    }

    /* Build: jmp returnVA (5 bytes) */
    {
        UINT64 ins = sc_base + p;
        INT32 d = (INT32)((INT64)returnVA - (INT64)(ins + 5));
        sc[p++] = 0xE9;
        *(INT32*)(sc + p) = d;
        p += 4;
    }

    return p;
}

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void MSpeed_OnAttach(void)
{
    MUTATE_START
    WriteLogFile("MSpeed: A enter");
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) { WriteLogFile("MSpeed: B no cr3/base"); goto _ms_end; }

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_ms_pat, k_ms_mask, 15);
        BYOVD_UNLOCK();
    }
    { char b[80]; wsprintfA(b,"MSpeed: D matchVA=0x%I64X",matchVA); WriteLogFile(b); }
    if (!matchVA) { WriteLogFile("MSpeed: E AOB NOT FOUND"); goto _ms_end; }


    s_hookVA = matchVA + MS_AOB_OFF;
    { char b[80]; wsprintfA(b,"MSpeed: F hookVA=0x%I64X",s_hookVA); WriteLogFile(b); }

    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, MS_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    if (!s_caveVA) { WriteLogFile("MSpeed: G cave not found"); s_hookVA=0; goto _ms_end; }

    s_scVA = s_caveVA + MS_DATA_OFF;
    WriteLogFile("MSpeed: Z OK");
_ms_end:
    MUTATE_END
}
#pragma optimize("", on)

void MSpeed_SetValue(float val)
{
    if (val < 1.0f) val = 1.0f;
    if (val > 10.0f) val = 10.0f;
    s_value = val;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_caveVA + MS_OFF_VALUE, &s_value, 4);
    BYOVD_UNLOCK();
}

void MSpeed_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !MSpeed_IsReady()) return;
    s_enabled = state;

    if (state) {
        if (s_hookId != -1) return;

        UINT8 cave[MS_CAVE_NEED]; memset(cave, 0, sizeof(cave));
        *(float*)(cave + MS_OFF_VALUE) = s_value;

        int scLen = Build_Shellcode(cave, s_caveVA, s_hookVA);

        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA, cave, MS_DATA_OFF + scLen);
        BYOVD_UNLOCK();

        s_hookId = LazyHook_Install(cr3, s_hookVA, MS_STOLEN_LEN,
                                    cave + MS_DATA_OFF, (UINT32)scLen, s_scVA);
        if (s_hookId == -1) s_enabled = FALSE;
    } else {
        if (s_hookId != -1) { LazyHook_Remove(s_hookId, cr3); s_hookId = -1; }
    }
}

#pragma optimize("", off)
void MSpeed_OnDetach(void)
{
    MUTATE_START
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId != -1 && cr3) LazyHook_Remove(s_hookId, cr3);
    s_hookVA=0; s_caveVA=0; s_scVA=0; s_hookId=-1; s_enabled=FALSE;
    MUTATE_END
}
#pragma optimize("", on)

