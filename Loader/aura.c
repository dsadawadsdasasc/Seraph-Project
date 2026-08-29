
#include "ThemidaSDK.h"
#include "aura.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "lazyhook.h"
#include "cave_finder.h"
#include "debug.h"
#include "esp.h"  /* g_EspState.keys_valid — aura code lazy-loads with the key region */
#include <string.h>

/* Immune Aura — direct port of the legacy CE script.
 *
 * AOB anchor (current build, 12 bytes — extended past the legacy 7-byte
 * pattern because the same 7 bytes also match the chams function; the
 * tail `F3 41 0F 7F 03` (movdqu [r11],xmm0) is the loop variant's
 * fingerprint and uniquely identifies the aura site):
 *   0F 10 02              movups xmm0, [rdx]            <-- hook here
 *   48 83 C1 60           add    rcx, 60h
 *   F3 41 0F 7F 03        movdqu [r11], xmm0
 *
 * Stolen at hookVA = matchVA + 0  (7 bytes, two full instructions):
 *   0F 10 02        movups xmm0, [rdx]   (3 bytes)
 *   48 83 C1 60     add    rcx, 60h     (4 bytes)
 * LazyHook writes JMP rel32 (5) + 2-byte NOP padding at the hook site.
 *
 * Behavior (matches legacy CE):
 *   if enabled: xmm0[0:4] = aura_float ; rcx += 60 ; jmp back  (SKIPS stolen)
 *   else:       fall through to stolen — movups xmm0,[rdx] ; add rcx,60
 *
 * Why skip stolen when enabled: the original `movups xmm0,[rdx]` would
 * overwrite the constant we just wrote into xmm0.  Our shellcode emits
 * its own `add rcx,60` and a direct JMP to (hookVA + stolenLen), which
 * matches the LazyHook return target — so both paths converge correctly.
 *
 * Cave layout:
 *   +0x00  uint8 enabled              (runtime gate)
 *   +0x01..0x03 padding
 *   +0x04  float aura_value           (live-updated by SetMultiplier)
 *   +0x08  shellcode (~30 bytes)
 *   stolen + jmp back appended by LazyHook (only the disabled path uses them).
 */








#define AURA_AOB_LEN     8
#define AURA_AOB_OFF     0x00 /* hook target = matchVA */
#define AURA_STOLEN_LEN  8    /* movups xmm0,[r8] (4) + add rcx,30h (4) */
#define AURA_DATA_OFF    0x0C /* shellcode begins this far into the cave */
#define AURA_CAVE_NEED   96   /* actual ~77 incl. data(12)+sc(52)+stolen(8)+jmp(5) */

#define AURA_OFF_ENABLED  0x00
#define AURA_OFF_VALUE    0x04
#define AURA_OFF_DURATION 0x08

static UINT64 s_preScanVA   = 0;
static UINT64 s_hookVA      = 0;
static UINT64 s_caveVA      = 0;
static UINT64 s_scVA        = 0;
static int    s_hookId      = -1;
static int    s_auraValue   = 4;
static BOOL   s_enabled     = FALSE;

void Aura_SetPreScanResult(UINT64 va) { s_preScanVA = va; }

#include "aob_patterns.h"

#pragma optimize("", off)
void Aura_OnAttach(void) {
    MUTATE_START
    WriteLogFile("Aura: A enter");
    s_hookVA = 0; s_caveVA = 0; s_scVA = 0; s_hookId = -1;
    s_auraValue = 4; s_enabled = FALSE;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    {char b[80]; wsprintfA(b,"Aura: B cr3=0x%I64X base=0x%I64X",cr3,d2Base); WriteLogFile(b);}
    if (!cr3 || !d2Base) goto _aoa_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        BYOVD_LOCK();
        matchVA = BYOVD_ScanPatternText(cr3, d2Base, k_aura_pat, k_aura_mask, 8);
        BYOVD_UNLOCK();
    }
    if (!matchVA) {
        WriteLogFile("Aura: AOB match failed");
        s_hookVA = 0;
        goto _aoa_end;
    }
    s_hookVA = matchVA + AURA_AOB_OFF;
    {char b[80]; wsprintfA(b,"Aura: I hookVA=0x%I64X CaveFinder_FindNear START",s_hookVA); WriteLogFile(b);}

    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, AURA_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    {char b[80]; wsprintfA(b,"Aura: J CaveFinder DONE caveVA=0x%I64X",s_caveVA); WriteLogFile(b);}
    if (!s_caveVA) {
        WriteLogFile("Aura: K cave not found");
        s_hookVA = 0;
        goto _aoa_end;
    }
    s_scVA = s_caveVA + AURA_DATA_OFF;
    WriteLogFile("Aura: L OK");
_aoa_end:
    WriteLogFile("Aura: Z exit");
    MUTATE_END
}
#pragma optimize("", on)

BOOL Aura_IsReady(void) {
    return s_hookVA != 0 && s_caveVA != 0;
}

void Aura_SetMultiplier(int multValue) {
    s_auraValue = multValue;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    float fval = (float)s_auraValue;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_caveVA + AURA_OFF_VALUE, &fval, 4);
    BYOVD_UNLOCK();
}

int Aura_GetMultiplier(void) {
    return s_auraValue;
}

/* Build shellcode (~30 bytes).  hookVA + AURA_STOLEN_LEN is the address the
 * game expects to resume at after the hook patch — same place LazyHook's
 * appended JMP back targets.
 *
 *   push rax
 *   movzx eax, byte [rip+enabled]
 *   test al, al
 *   pop rax                            <- restore BEFORE branch (ZF preserved)
 *   jz fallthrough                     <- fall to stolen if disabled
 *   movss xmm0, dword [rip+aura_value] <- replace the would-be movups
 *   add rcx, 60                        <- replicate the second stolen instr
 *   jmp (hookVA + stolenLen)           <- skip stolen entirely
 *   fallthrough:                       <- (LazyHook places stolen here)
 */
static int Build_Shellcode(UINT8 *cave, UINT64 cave_base, UINT64 hookVA)
{
    UINT64 sc_base      = cave_base + AURA_DATA_OFF;
    UINT8 *sc           = cave + AURA_DATA_OFF;
    UINT64 enabledVA    = cave_base + AURA_OFF_ENABLED;
    UINT64 valueVA      = cave_base + AURA_OFF_VALUE;
    UINT64 durationVA   = cave_base + AURA_OFF_DURATION;
    UINT64 returnVA     = hookVA + AURA_STOLEN_LEN;
    int p = 0;

    /* push rax    50 */
    sc[p++] = 0x50;

    /* movzx eax, byte [rip+enabled]    0F B6 05 disp32   (7 bytes) */
    {
        UINT64 instr = sc_base + p;
        INT32 disp = (INT32)((INT64)enabledVA - (INT64)(instr + 7));
        sc[p++] = 0x0F; sc[p++] = 0xB6; sc[p++] = 0x05;
        *(INT32*)(sc + p) = disp; p += 4;
    }

    /* test al, al    84 C0 */
    sc[p++] = 0x84; sc[p++] = 0xC0;

    /* pop rax    58 */
    sc[p++] = 0x58;

    /* jz fallthrough    74 ??   (short — skips our 39-byte do-work block) */
    int jzPos = p;
    sc[p++] = 0x74; sc[p++] = 0x00;

    /* --- ACTIVATED PATH --- */

    /* 1. movups xmm0, [r8]    41 0F 10 00  (4 bytes) */
    sc[p++] = 0x41; sc[p++] = 0x0F; sc[p++] = 0x10; sc[p++] = 0x00;

    /* 2. movss xmm1, dword [rip+aura_value]    F3 0F 10 0D disp32   (8 bytes) */
    {
        UINT64 instr = sc_base + p;
        INT32 disp = (INT32)((INT64)valueVA - (INT64)(instr + 8));
        sc[p++] = 0xF3; sc[p++] = 0x0F; sc[p++] = 0x10; sc[p++] = 0x0D;
        *(INT32*)(sc + p) = disp; p += 4;
    }

    /* 3. movss xmm0, xmm1    F3 0F 10 C1  (4 bytes) */
    sc[p++] = 0xF3; sc[p++] = 0x0F; sc[p++] = 0x10; sc[p++] = 0xC1;

    /* 4. movss xmm1, dword [rip+aura_duration]    F3 0F 10 0D disp32   (8 bytes) */
    {
        UINT64 instr = sc_base + p;
        INT32 disp = (INT32)((INT64)durationVA - (INT64)(instr + 8));
        sc[p++] = 0xF3; sc[p++] = 0x0F; sc[p++] = 0x10; sc[p++] = 0x0D;
        *(INT32*)(sc + p) = disp; p += 4;
    }

    /* 5. insertps xmm0, xmm1, 0x30    66 0F 3A 21 C1 30  (6 bytes) */
    sc[p++] = 0x66; sc[p++] = 0x0F; sc[p++] = 0x3A; sc[p++] = 0x21; sc[p++] = 0xC1; sc[p++] = 0x30;

    /* 6. add rcx, 30h    48 83 C1 30   (4 bytes) */
    sc[p++] = 0x48; sc[p++] = 0x83; sc[p++] = 0xC1; sc[p++] = 0x30;

    /* 7. jmp returnVA    E9 disp32   (5 bytes) */
    {
        UINT64 instr = sc_base + p;
        INT32 disp = (INT32)((INT64)returnVA - (INT64)(instr + 5));
        sc[p++] = 0xE9;
        *(INT32*)(sc + p) = disp; p += 4;
    }

    /* fallthrough: stolen runs here (LazyHook appends after our shellcode) */
    int fallPos = p;

    /* Patch jz to point at fallPos */
    INT8 jzDelta = (INT8)(fallPos - (jzPos + 2));
    sc[jzPos + 1] = (UINT8)jzDelta;

    return p;
}

void Aura_SetEnabled(BOOL state) {
    if (s_enabled == state) return;
    s_enabled = state;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !Aura_IsReady()) return;

    if (state) {
        if (s_hookId != -1) return;

        UINT8 cave[AURA_CAVE_NEED];
        memset(cave, 0, sizeof(cave));
        cave[AURA_OFF_ENABLED] = 1;
        float fval = (float)s_auraValue;
        *(float*)(cave + AURA_OFF_VALUE) = fval;
        float fdur = 300.0f;
        *(float*)(cave + AURA_OFF_DURATION) = fdur;

        int scLen = Build_Shellcode(cave, s_caveVA, s_hookVA);
        if (scLen <= 0 || scLen + AURA_DATA_OFF + AURA_STOLEN_LEN + 5 > AURA_CAVE_NEED) {
            DEBUG_AURA("Aura: shellcode build failed (len=%d)", scLen);
            s_enabled = FALSE;
            return;
        }

        BYOVD_LOCK();
        BOOL ok = BYOVD_WriteVA(cr3, s_caveVA, cave, AURA_DATA_OFF);
        BYOVD_UNLOCK();
        if (!ok) {
            DEBUG_AURA("Aura: cave data write failed");
            s_enabled = FALSE;
            return;
        }

        s_hookId = LazyHook_Install(cr3, s_hookVA, AURA_STOLEN_LEN,
                                    cave + AURA_DATA_OFF, (UINT32)scLen, s_scVA);
        DEBUG_AURA("Aura_SetEnabled: hook id=%d (scLen=%d val=%d)", s_hookId, scLen, s_auraValue);
        if (s_hookId == -1) s_enabled = FALSE;
    } else {
        if (s_hookId != -1) {
            LazyHook_Remove(s_hookId, cr3);
            s_hookId = -1;
            DEBUG_AURA("Aura_SetEnabled: hook removed");
        }
        UINT8 zero = 0;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, s_caveVA + AURA_OFF_ENABLED, &zero, 1);
        BYOVD_UNLOCK();
    }
}

void Aura_Tick(void) {
    /* No-op: SetMultiplier writes the float directly to the cave. */
    (void)0;
}

#pragma optimize("", off)
void Aura_OnDetach(void) {
    MUTATE_START
    if (s_hookId != -1) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) LazyHook_Remove(s_hookId, cr3);
    }
    s_hookVA = 0; s_caveVA = 0; s_scVA = 0; s_hookId = -1;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

