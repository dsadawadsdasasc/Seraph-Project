
#include "ThemidaSDK.h"
#include "instakill.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"

/* InstaKill — forces all enemy HP writes to 0.0 on the stack.
 *
 * AOB (17 bytes):
 *   F3 0F 11 44 24 50   movss [rsp+50h], xmm0   <- HOOK HERE (6 bytes stolen)
 *   33 C0               xor   eax, eax
 *   8B 5C 24 50         mov   ebx, [rsp+50h]
 *   B9 DD AD 93 43      mov   ecx, 4393ADDDh
 *
 * Shellcode: load 0.0 into xmm0 via RIP-relative, jmp over stolen bytes.
 *
 * Cave layout (LazyHook appends stolen + jmp back):
 *   cave+0:  F3 0F 10 05 02 00 00 00   movss xmm0, [rip+2]    (8 bytes)
 *                                       rip = cave+8, cave+8+2 = cave+10 (float)
 *   cave+8:  EB 0A                      jmp +10 -> cave+20     (2 bytes)
 *                                       skips float(4) + stolen(6) = 10 bytes
 *   cave+10: 00 00 00 00                0.0f                   (4 bytes)
 *   cave+14: [stolen 6 bytes]           skipped by EB 0A
 *   cave+20: E9 [rel32]                 jmp back to hookVA+6   (5 bytes)
 *
 * Total cave needed: 8 + 2 + 4 + 6 + 5 = 25 bytes
 */

/* AOB (CE script):
 *   F3 0F 11 44 24 50 33 C0 8B   (movss [rsp+0x50], xmm0 ; xor eax,eax ; mov ...)
 *   target = matchVA (hook on the movss directly, 6 bytes stolen).            */







#define IK_AOB_LEN    9
#define IK_AOB_OFF    0      /* hook target = matchVA */
#define IK_STOLEN_LEN  6
#define IK_CAVE_NEED  25
#define IK_SCAN_SIZE  0x20000000ULL  /* 512 MB */

static UINT64 s_preScanVA = 0;
static UINT64 s_hookVA  = 0;
static UINT64 s_caveVA  = 0;
static int    s_hookId  = -1;
static BOOL   s_enabled = FALSE;

void InstaKill_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#include "xor_strings.h"

#include "aob_patterns.h"

#pragma optimize("", off)
void InstaKill_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_caveVA = 0; s_hookId = -1; s_enabled = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _ikoa_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) goto _ikoa_end;
    s_hookVA = matchVA + IK_AOB_OFF;



    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindFirst(cr3, d2Base, IK_CAVE_NEED);
    BYOVD_UNLOCK();
    if (!s_caveVA) goto _ikoa_end;
_ikoa_end:
    MUTATE_END
}
#pragma optimize("", on)

BOOL InstaKill_IsReady(void)
{
    return s_hookVA != 0 && s_caveVA != 0;
}

BOOL InstaKill_IsEnabled(void)
{
    return s_enabled;
}

void InstaKill_SetEnabled(BOOL state)
{
    if (s_enabled == state) return;
    s_enabled = state;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !InstaKill_IsReady()) return;

    if (state) {
        if (s_hookId == -1) {
            /* movss xmm0, [rip+2]  (8 bytes) + jmp +10 (2 bytes) + 0.0f (4 bytes)
             * rip after movss = cave+8, cave+8+2 = cave+10 where 0.0f lives.
             * EB 0A skips the 4-byte float + 6-byte stolen = 10 bytes -> lands on jmp back. */
            const UINT8 sc[] = {
                0xF3, 0x0F, 0x10, 0x05, 0x02, 0x00, 0x00, 0x00, /* movss xmm0,[rip+2] */
                0xEB, 0x0A,                                       /* jmp +10            */
                0x00, 0x00, 0x00, 0x00                            /* 0.0f               */
            };

            s_hookId = LazyHook_Install(cr3, s_hookVA, IK_STOLEN_LEN,
                                        sc, sizeof(sc), s_caveVA);
        }
    } else {
        if (s_hookId != -1) {
            LazyHook_Remove(s_hookId, cr3);
            s_hookId = -1;
        }
    }
}

#pragma optimize("", off)
void InstaKill_OnDetach(void)
{
    MUTATE_START
    if (s_hookId != -1) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
    }
    s_hookVA = 0; s_caveVA = 0; s_hookId = -1; s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

