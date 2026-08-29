/* Silent Aim — code-cave approach matching the vanish/tiger reference.
 *
 * AOB (23 bytes — last byte E9 is an anchor, NOT part of the patch):
 *   0F 10 04 C1              movups xmm0,[rcx+rax*8]
 *   0F 29 85 ?? ?? ?? ??     movaps [rbp+disp32],xmm0
 *   0F 11 03                 movups [rbx],xmm0
 *   44 0F 28 BD ?? ?? ?? ??  movaps xmm15,[rbp+disp32]
 *   E9                       jmp ... (anchor byte, not patched)
 *
 * Hook patch (22 bytes at matchVA):
 *   E9 xx xx xx xx           JMP rel32 → cave
 *   90 90 ... (×17)          NOPs filling the rest
 *
 * Cave layout (cave_va + offset):
 *   +0x00  EB 0C             short JMP +12 — skips the 3 floats below
 *   +0x02  float allMark     1.643928318E35f
 *   +0x06  float cone        configurable  ← SA_CONE_OFF
 *   +0x0A  float snipMark    1.210828771E-7f
 *   +0x0E  [76 bytes SC]     RIP-relative shellcode (hardcoded disps)
 *   +0x5A  [22 bytes]        original stolen bytes
 *   +0x70  E9 xx xx xx xx    JMP back to hookVA+22
 * Total: 0x75 = 117 bytes — use 128 to be safe.
 *
 * Shellcode semantics (identical to vanish reference):
 *   xmm2 = allMark
 *   xmm0 = *(float*)(rcx+rax*8 - 0x48)        ← game marker
 *   if (xmm0 == allMark) → write cone to [rcx+rax*8] and [rcx+rax*8+0x50]
 *   xmm2 = snipMark
 *   xmm0 = *(float*)(rcx+rax*8 - 0x48)        ← re-read marker
 *   if (xmm0 == snipMark) → write cone to [rcx+rax*8] and [rcx+rax*8+0x10]
 *   then execute original 22 bytes + JMP back
 *
 * RIP-relative displacement verification (cave layout above):
 *   inst @ 0x0E: rip=0x16, disp=-20 → target=0x02 (allMark)   ✓
 *   inst @ 0x21: rip=0x29, disp=-35 → target=0x06 (cone)       ✓
 *   inst @ 0x34: rip=0x3C, disp=-50 → target=0x0A (snipMark)  ✓
 *   inst @ 0x47: rip=0x4F, disp=-73 → target=0x06 (cone)       ✓
 */

#include "ThemidaSDK.h"
#include "xor_strings.h"
#include "silent_aim.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include <string.h>

/* ── AOB ──────────────────────────────────────────────────────────────────── */







#define SA_AOB_LEN    23          /* total pattern length (includes E9 anchor)  */
#define SA_HOOK_LEN   22          /* bytes actually patched at hook site         */
#define SA_CONE_OFF   0x06        /* float cone inside cave (cave_va + 0x06)     */
#define SA_CAVE_NEED  128         /* bytes needed (117 actual, 128 for safety)   */

/* allMark / snipMark constants from the game's bullet-magnetism function */
#define SA_ALL_MARK   1.643928318E35f
#define SA_SNIP_MARK  1.210828771E-7f

static UINT64 s_preScanVA   = 0;
static UINT64 s_hookVA      = 0;   /* VA of the 22-byte patch site              */
static UINT64 s_caveVA      = 0;   /* VA of the code cave                       */
static BOOL   s_enabled     = FALSE;
static float  s_coneValue   = 100.0f;
static UINT8  s_stolenBytes[SA_HOOK_LEN]; /* saved original bytes for restore  */

void SilentAim_SetPreScanResult(UINT64 va) { s_preScanVA = va; }
BOOL SilentAim_IsReady(void)               { return s_hookVA != 0 && s_caveVA != 0; }
BOOL SilentAim_IsEnabled(void)             { return s_enabled; }

void SilentAim_SetMagnetism(float coneDeg)
{
    s_coneValue = coneDeg;
    if (s_caveVA && s_enabled) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_caveVA + SA_CONE_OFF, &s_coneValue, 4);
            BYOVD_UNLOCK();
        }
    }
}

/* SilentAim_ReadSpy — not used in the new approach, kept for ABI compat */
BOOL SilentAim_ReadSpy(UINT32 *out_count, float *out_marker)
{
    (void)out_count; (void)out_marker;
    return FALSE;
}

/* ── Build cave buffer ────────────────────────────────────────────────────── *
 * Fills cave_buf (SA_CAVE_NEED bytes) with:
 *   header + floats + shellcode + original bytes + JMP back               */
static void Build_Cave(UINT8 *cave_buf, UINT64 cave_va,
                       const UINT8 *stolen22, float cone)
{
    memset(cave_buf, 0x90, SA_CAVE_NEED); /* fill with NOPs */

    /* ── Header ─────────────────────────────────────────────────────────── */
    cave_buf[0x00] = 0xEB;
    cave_buf[0x01] = 0x0C; /* short JMP +12 → skip to 0x0E */

    /* ── Floats ──────────────────────────────────────────────────────────── */
    *(float*)(cave_buf + 0x02) = SA_ALL_MARK;
    *(float*)(cave_buf + 0x06) = cone;            /* ← SA_CONE_OFF = 0x06 */
    *(float*)(cave_buf + 0x0A) = SA_SNIP_MARK;

    /* ── Shellcode @ cave+0x0E ───────────────────────────────────────────── *
     * All RIP-relative displacements are hardcoded (verified above).        */
    UINT8 *s = cave_buf + 0x0E;
    int p = 0;

    /* movss xmm2,[rip-20] → cave+0x02 (allMark) */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x15;
    *(INT32*)(s+p) = (INT32)0xFFFFFFEC; p += 4;

    /* movss xmm0,[rcx+rax*8-0x48] */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x44; s[p++]=0xC1; s[p++]=0xB8;

    /* ucomiss xmm0,xmm2 */
    s[p++]=0x0F; s[p++]=0x2E; s[p++]=0xC2;

    /* jne +0x13 (to snipMark check at p=0x34-0x0E=0x26) */
    s[p++]=0x75; s[p++]=0x13;

    /* movss xmm2,[rip-35] → cave+0x06 (cone) */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x15;
    *(INT32*)(s+p) = (INT32)0xFFFFFFDD; p += 4;

    /* movss [rcx+rax*8],xmm2 */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x11; s[p++]=0x14; s[p++]=0xC1;

    /* movss [rcx+rax*8+0x50],xmm2 — DISABLED: crashes during ability use.
     * 6 NOPs preserve the jne +0x13 layout. */
    s[p++]=0x90; s[p++]=0x90; s[p++]=0x90; s[p++]=0x90; s[p++]=0x90; s[p++]=0x90;

    /* (jne from allMark check jumps here — p=0x26) */

    /* movss xmm2,[rip-50] → cave+0x0A (snipMark) */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x15;
    *(INT32*)(s+p) = (INT32)0xFFFFFFCE; p += 4;

    /* movss xmm0,[rcx+rax*8-0x48] */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x44; s[p++]=0xC1; s[p++]=0xB8;

    /* ucomiss xmm0,xmm2 */
    s[p++]=0x0F; s[p++]=0x2E; s[p++]=0xC2;

    /* jne +0x13 (to passthrough / original bytes at p=0x4C) */
    s[p++]=0x75; s[p++]=0x13;

    /* movss xmm2,[rip-73] → cave+0x06 (cone) */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x10; s[p++]=0x15;
    *(INT32*)(s+p) = (INT32)0xFFFFFFB7; p += 4;

    /* movss [rcx+rax*8],xmm2 */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x11; s[p++]=0x14; s[p++]=0xC1;

    /* movss [rcx+rax*8+0x10],xmm2 */
    s[p++]=0xF3; s[p++]=0x0F; s[p++]=0x11; s[p++]=0x54; s[p++]=0xC1; s[p++]=0x10;

    /* (jne from snipMark check jumps here — p=0x4C) */
    /* p should now == 0x4C, offset in cave = 0x0E + 0x4C = 0x5A */

    /* ── Original 22 bytes ───────────────────────────────────────────────── */
    memcpy(cave_buf + 0x5A, stolen22, SA_HOOK_LEN); /* ends at 0x5A+22 = 0x70 */

    /* ── JMP back to hookVA + 22 ─────────────────────────────────────────── */
    UINT64 jmp_from = cave_va + 0x70;
    UINT64 ret_va   = s_hookVA + SA_HOOK_LEN;
    INT32  jmp_disp = (INT32)((INT64)ret_va - (INT64)(jmp_from + 5));
    cave_buf[0x70] = 0xE9;
    *(INT32*)(cave_buf + 0x71) = jmp_disp;
}

#pragma optimize("", off)
void SilentAim_OnAttach(void)
{
    MUTATE_START
    s_hookVA = 0; s_caveVA = 0;
    s_enabled = FALSE;
    memset(s_stolenBytes, 0, sizeof(s_stolenBytes));

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) goto _end;

    /* ── RVA resolution ─────────────────────────────────────────────────── */
    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        matchVA = d2Base + SecureReadStatic(&OBF_OFF_SilentAim);
    }
    s_hookVA = matchVA; /* patch starts at match offset 0 */


    /* ── Save original bytes ─────────────────────────────────────────────── */
    {
        BYOVD_LOCK();
        BOOL rd = BYOVD_ReadVA(cr3, s_hookVA, s_stolenBytes, SA_HOOK_LEN);
        BYOVD_UNLOCK();
        if (!rd) {
            DEBUG_FLY("SilentAim_OnAttach: failed to read original bytes");
            s_hookVA = 0;
            goto _end;
        }
    }

    /* ── Find code cave ──────────────────────────────────────────────────── */
    BYOVD_LOCK();
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, SA_CAVE_NEED, s_hookVA);
    BYOVD_UNLOCK();
    if (!s_caveVA) {
        DEBUG_FLY("SilentAim_OnAttach: cave not found");
        s_hookVA = 0;
        goto _end;
    }

    DEBUG_FLY("SilentAim_OnAttach: match=0x%I64X cave=0x%I64X", matchVA, s_caveVA);
_end:
    MUTATE_END
}
#pragma optimize("", on)

#pragma optimize("", off)
void SilentAim_OnDetach(void)
{
    MUTATE_START
    if (s_enabled) {
        /* Restore original bytes */
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3 && s_hookVA) {
            BYOVD_LOCK();
            BYOVD_WriteVA(cr3, s_hookVA, s_stolenBytes, SA_HOOK_LEN);
            BYOVD_UNLOCK();
        }
    }
    s_hookVA = 0; s_caveVA = 0;
    s_enabled = FALSE;
    MUTATE_END
}
#pragma optimize("", on)

void SilentAim_SetEnabled(BOOL state)
{
    if (s_enabled == (state ? TRUE : FALSE)) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !SilentAim_IsReady()) return;

    if (state) {
        /* ── Verify if the memory has already been altered ────────────────── */
        UINT8 currentBytes[SA_HOOK_LEN];
        BYOVD_LOCK();
        BOOL readOk = BYOVD_ReadVA(cr3, s_hookVA, currentBytes, SA_HOOK_LEN);
        BYOVD_UNLOCK();
        if (!readOk) {
            DEBUG_FLY("SilentAim: failed to read hook location for verification");
            return;
        }
        if (currentBytes[0] != 0x0F && currentBytes[0] != 0xE9) {
            DEBUG_FLY("SilentAim: verification failed! Hook site byte 0 = 0x%02X", currentBytes[0]);
            return;
        }

        /* ── Build and write cave ─────────────────────────────────────────── */
        UINT8 cave_buf[SA_CAVE_NEED];
        Build_Cave(cave_buf, s_caveVA, s_stolenBytes, s_coneValue);

        BYOVD_LOCK();
        BOOL ok = BYOVD_WriteVA(cr3, s_caveVA, cave_buf, SA_CAVE_NEED);
        BYOVD_UNLOCK();
        if (!ok) {
            DEBUG_FLY("SilentAim: cave write failed");
            return;
        }

        /* ── Patch hook site: JMP to cave + NOPs ──────────────────────────── */
        UINT8 patch[SA_HOOK_LEN];
        memset(patch, 0x90, SA_HOOK_LEN); /* NOPs */
        patch[0] = 0xE9;
        INT32 jmp_disp = (INT32)((INT64)s_caveVA - (INT64)(s_hookVA + 5));
        *(INT32*)(patch + 1) = jmp_disp;

        BYOVD_LOCK();
        ok = BYOVD_WriteVA(cr3, s_hookVA, patch, SA_HOOK_LEN);
        BYOVD_UNLOCK();
        if (!ok) {
            DEBUG_FLY("SilentAim: hook patch write failed");
            return;
        }

        s_enabled = TRUE;
        DEBUG_FLY("SilentAim: enabled (cone=%.1f caveVA=0x%I64X jmp_disp=%d)",
                  s_coneValue, s_caveVA, (int)jmp_disp);

    } else {
        /* ── Restore original bytes ───────────────────────────────────────── */
        BYOVD_LOCK();
        BOOL ok = BYOVD_WriteVA(cr3, s_hookVA, s_stolenBytes, SA_HOOK_LEN);
        BYOVD_UNLOCK();
        if (!ok) {
            DEBUG_FLY("SilentAim: restore failed");
            return;
        }
        s_enabled = FALSE;
        DEBUG_FLY("SilentAim: disabled");
    }
}
