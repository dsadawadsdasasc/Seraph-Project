#ifndef SERAPH_DMA_BUILD
/* ammo.c -- Infinite Ammo via in-cave shellcode with correct encryption.
 *
 * Reference: Rust implementation (set_infinite_ammo / GetEncryptedAmmo).
 *
 * Pattern (finds JMP into ammo function body):
 *   E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 5F 08
 *   Resolve the E9 rel32 to get hookVA  (offset 0x1 in match → +5 adds to get target)
 *
 * get_ammo_key pattern:
 *   E8 ?? ?? ?? ?? 33 C3 41 89 84 24
 *   Resolve the CALL rel32 at offset 0x0.
 *
 * Stolen bytes at hookVA (6 bytes):
 *   44 8B 07   mov r8d, [rdi]
 *   41 8B C0   mov eax, r8d
 *
 * Cave layout (offsets from caveBaseVA):
 *   [cave + 0x00]  8 bytes  : enabled flag (QWORD: 1=on, 0=off)
 *   [cave + 0x08]  8 bytes  : get_ammo_key absolute VA
 *   [cave + 0x10]  shellcode: LazyHook writes our SC here → caveVA passed to LazyHook
 *   4. Read ammo_encrypted = [rdi + 0x1AA4]
 *   5. Call get_ammo_key → eax = key
 *   6. ammo_raw = ammo_encrypted XOR key           (decrypt)
 *   7. ammo_raw += 1                               (increment)
 *   8. Run GetEncryptedAmmo(ammo_raw) → ebx        (re-encrypt)
 *   9. Write ebx → [rdi + 0x1AA4]
 *  10. Restore regs, ret (LazyHook appends stolen+jmpback)
 *
 * GetEncryptedAmmo(uint32 raw) (matches reference C & Rust):
 *   eax = raw ^ 0xF9DB
 *   edx = (raw & 0xFFFF) << 16
 *   ebx = (raw >> 16) | edx          ; ROL raw, 16
 *   ebx ^= eax
 *   eax = (ebx ^ 0x0762) & 0xFFFF
 *   ebx = ROR(ebx, 16) ^ eax
 *   eax = (ebx ^ 0x957C) & 0xFFFF
 *   ebx = ROL(ebx, 16) ^ eax
 *   eax = (ebx ^ 0x367E) & 0xFFFF
 *   ebx = ROL(ebx, 16) ^ eax
 *   ebx = ROL(ebx, 16)
 *   return key ^ ebx                 (caller XORs with key — we fold that into step 8)
 *
 * NOTE on how we fold the key XOR:
 *   The reference does:  result = GetEncryptedAmmo(raw+1) XOR key
 *   which is:  (key XOR ebx_after_state_machine) XOR key = ebx_after_state_machine? NO.
 *   Actually the reference C GetEncryptedAmmo returns encryptionKey3 ^ ebx,
 *   and the Rust does xor eax, ebx then writes dword [rdi+0x1AA4].
 *   So:  write_value = get_ammo_key_result XOR GetEncryptedAmmo_ebx_before_key_xor
 *   We handle this by: state machine produces ebx; then write = key XOR ebx.
 */

#include "ammo.h"
#include "byovd.h"
#include "attach.h"
#include "cave_finder.h"
#include "lazyhook.h"
#include "fly.h"
#include "byovd_lock.h"
#include "debug.h"
#include <windows.h>
#include <string.h>
#include "aob_patterns.h"



#define AMMO_STOLEN_LEN   6
#define AMMO_SCAN_SIZE    0x8000000ULL   /* 128 MB */
#define AMMO_TICK_MS      16

/* ── Cave data offsets ────────────────────────────────────────────────── */
#define CAVE_OFF_ENABLED  0x00   /* QWORD: 1=enabled, 0=disabled */
#define CAVE_OFF_GETKEY   0x08   /* QWORD: absolute VA of get_ammo_key */
#define CAVE_OFF_VALUE    0x10   /* DWORD: ammo value override (0 = infinite ammo) */
#define CAVE_OFF_SC       0x18   /* shellcode starts here */

/* ── State ────────────────────────────────────────────────────────────── */
static UINT64 s_caveVA   = 0;
static UINT32 s_caveSize = 0;
static int    s_hookId   = -1;
static UINT64 s_hookVA   = 0;
static UINT64 s_getKeyVA = 0;
static BOOL   s_enabled  = FALSE;
static UINT32 s_customVal = 0;

/* ── Resolve E9 JMP target ────────────────────────────────────────────── */
static UINT64 ResolveJmpTarget(UINT64 cr3, UINT64 matchVA)
{
    INT32 rel = 0;
    if (!BYOVD_ReadVA(cr3, matchVA + 1, &rel, 4)) return 0;
    return (UINT64)((INT64)(matchVA + 5) + rel);
}

/* ── Resolve CALL target ──────────────────────────────────────────────── */
static UINT64 ResolveCallTarget(UINT64 cr3, UINT64 matchVA)
{
    INT32 rel = 0;
    if (!BYOVD_ReadVA(cr3, matchVA + 1, &rel, 4)) return 0;
    return (UINT64)((INT64)(matchVA + 5) + rel);
}

/* ── FindAmmoCave (avoid collision with fly.c) ───────────────────────── */
static void FindAmmoCave(UINT64 cr3, UINT64 d2Base)
{
    CaveInfo caves[16];
    int n = CaveFinder_Scan(cr3, d2Base, 32, caves, 16);
    UINT64 flyCave = Fly_GetCaveVA();

    for (int i = 0; i < n; i++) {
        if (flyCave &&
            caves[i].va + caves[i].size > flyCave - 0x1000 &&
            caves[i].va                 < flyCave + 0x1000)
            continue;
        if (caves[i].size >= 256) {
            s_caveVA   = caves[i].va;
            s_caveSize = caves[i].size;
            DEBUG_FLY("Ammo cave: VA=0x%I64X size=%u", s_caveVA, s_caveSize);
            return;
        }
    }
    DEBUG_FLY("Ammo: no suitable cave found");
}

/* ── Build and install shellcode ─────────────────────────────────────── */
/*
 * Shellcode layout (placed at scBaseVA = caveVA + CAVE_OFF_SC):
 *
 *  +00  44 8B 07           mov r8d, [rdi]           ; stolen byte group 1
 *  +03  45 8B C0           mov eax, r8d             ; stolen byte group 2
 *  +06  48 83 3D XX XX XX XX 00  cmp qword[rip+disp_flag], 0  ; check enabled
 *  +0E  74 ??              jz  <to_ret>             ; skip if disabled
 *  --- save regs ---
 *  +10  57                 push rdi
 *  +11  51                 push rcx
 *  +12  52                 push rdx
 *  +13  41 50              push r8
 *  +15  41 51              push r9
 *  +17  41 52              push r10
 *  +19  41 53              push r11
 *  +1B  48 83 EC 28        sub  rsp, 0x28           ; shadow space + align
 *  --- read ammo_encrypted ---
 *  +1F  44 8B B7 A4 1A 00 00  mov r14d, [rdi+0x1AA4]  ; ammo_encrypted in r14d
 *       (we use r14d to avoid clobbering ebx which we need later)
 *       Actually use a caller-saved: we saved r8-r11, rcx, rdx. Use edx for ammo.
 *       8B 97 A4 1A 00 00    mov edx, [rdi+0x1AA4]
 *  +1F  8B 97 A4 1A 00 00   mov edx, [rdi+0x1AA4]  ; edx = ammo_encrypted
 *  --- call get_ammo_key ---
 *  +25  48 8B 05 XX XX XX XX  mov rax, [rip+disp_key]  ; load fn ptr
 *  +2C  FF D0              call rax                 ; eax = key
 *  --- decrypt: ammo_raw = ammo_encrypted XOR key ---
 *  +2E  33 C2              xor eax, edx             ; eax = raw = enc XOR key
 *  --- increment: ammo_raw += 1 ---
 *  +30  FF C0              inc eax                  ; eax = raw + 1
 *  --- GetEncryptedAmmo(eax) → ebx result ---
 *  +32  89 C3              mov ebx, eax             ; ebx = raw+1 (input)
 *  ; Step 1: eax = ebx ^ 0xF9DB
 *  +34  89 D8              mov eax, ebx
 *  +36  35 DB F9 00 00     xor eax, 0xF9DB
 *  ; Step 2: edx = (ebx & 0xFFFF) << 16
 *  +3B  89 DA              mov edx, ebx
 *  +3D  81 E2 FF FF 00 00  and edx, 0xFFFF
 *  +43  C1 E2 10           shl edx, 16
 *  ; Step 3: ebx = (ebx >> 16) | edx  → ROL(ebx,16)
 *  +46  C1 EB 10           shr ebx, 16
 *  +49  09 D3              or  ebx, edx
 *  ; Step 4: ebx ^= eax
 *  +4B  31 C3              xor ebx, eax
 *  ; Step 5: eax = (ebx ^ 0x0762) & 0xFFFF  (movzx)
 *  +4D  89 D8              mov eax, ebx
 *  +4F  35 62 07 00 00     xor eax, 0x0762
 *  +54  0F B7 C0           movzx eax, ax
 *  ; Step 6: ebx = ROR(ebx,16) ^ eax
 *  +57  C1 CB 10           ror ebx, 16
 *  +5A  31 C3              xor ebx, eax
 *  ; Step 7: eax = (ebx ^ 0x957C) & 0xFFFF
 *  +5C  89 D8              mov eax, ebx
 *  +5E  35 7C 95 00 00     xor eax, 0x957C
 *  +63  0F B7 C0           movzx eax, ax
 *  ; Step 8: ebx = ROL(ebx,16) ^ eax
 *  +66  C1 C3 10           rol ebx, 16
 *  +69  31 C3              xor ebx, eax
 *  ; Step 9: eax = (ebx ^ 0x367E) & 0xFFFF
 *  +6B  89 D8              mov eax, ebx
 *  +6D  35 7E 36 00 00     xor eax, 0x367E
 *  +72  0F B7 C0           movzx eax, ax
 *  ; Step 10: ebx = ROL(ebx,16) ^ eax
 *  +75  C1 C3 10           rol ebx, 16
 *  +78  31 C3              xor ebx, eax
 *  ; Step 11: ebx = ROL(ebx,16)  (final rotate)
 *  +7A  C1 C3 10           rol ebx, 16
 *  --- apply key: write_value = get_ammo_key() XOR ebx ---
 *  ; edx still has ammo_encrypted; eax = key from before? NO — eax was clobbered.
 *  ; We need to save the key. Save key in ecx (which we pushed, safe).
 *  ; BUT we already used ecx for push rcx. After sub rsp,0x28, [rsp+0x50]=rcx (see below).
 *  ; Instead: save key into a local on shadow space immediately after call.
 *  ; Revised approach: after call rax → eax=key, do:
 *  ;   mov ecx, eax   ; save key in ecx (after push rcx but before we use ecx for anything else)
 *  ;   xor eax, edx   ; eax = raw
 *  ;   inc eax        ; raw+1
 *  ;   ... state machine using eax/edx/ebx, ecx preserved as key ...
 *  ;   xor ebx, ecx   ; apply key to get final encrypted value
 *  ; This is the correct order - see revised shellcode below.
 *
 * REVISED FINAL SHELLCODE:
 * After call rax (key in eax):
 *   mov ecx, eax       ; ecx = key (save it)
 *   xor eax, edx       ; eax = raw ammo (enc XOR key)
 *   inc eax            ; eax = raw+1
 *   mov ebx, eax       ; ebx = raw+1 (for state machine)
 *   ... state machine produces ebx_encrypted ...
 *   xor ebx, ecx       ; apply key: result = sm_result XOR key
 *  ; Reload rdi from stack to write
 *   mov rdi, [rsp+0x58]  ; rdi was pushed 7th (6 r-pushes + rdi, then sub rsp,28)
 *                          ; stack: rsp+0=shadow, +28=r11, +30=r10, +38=r9,
 *                          ;        +40=r8, +48=rdx, +50=rcx, +58=rdi
 *   mov [rdi+0x1AA4], ebx ; write encrypted ammo
 *  ; restore
 *   add rsp, 0x28
 *   pop r11..pop rdi
 * <to_ret>:   (jz target)
 * --- LazyHook appends: stolen_bytes + JMP back ---
 */
#include "xor_strings.h"

static BOOL InstallAmmoHook(UINT64 cr3, UINT64 d2Base)
{
    if (s_hookId >= 0) return TRUE;
    if (!s_caveVA) return FALSE;
    if (!s_getKeyVA) return FALSE;

    UINT64 hookVA = d2Base + SecureReadStatic(&OBF_OFF_AmmoHookVA);
    s_hookVA = hookVA;
    DEBUG_FLY("Ammo: hookVA=0x%I64X getKeyVA=0x%I64X", hookVA, s_getKeyVA);

    /* --- write cave header --- */
    UINT64 zero = 0;
    if (!BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_ENABLED, &zero, 8)) return FALSE;
    if (!BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_GETKEY, &s_getKeyVA, 8)) return FALSE;
    if (!BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_VALUE, &s_customVal, 4)) return FALSE;

    /* --- build shellcode --- */
    UINT64 scBaseVA = s_caveVA + CAVE_OFF_SC;

    UINT8 sc[256];
    int   off = 0;

    /* Stolen bytes */
    /* 44 8B 07 */ sc[off++]=0x44; sc[off++]=0x8B; sc[off++]=0x07;
    /* 45 8B C0 */ sc[off++]=0x45; sc[off++]=0x8B; sc[off++]=0xC0;

    /* cmp qword ptr [rip+disp_flag], 0
     * Instruction is 8 bytes: 48 83 3D <disp32> 00
     * RIP after = scBaseVA + off + 8
     * target = caveVA + CAVE_OFF_ENABLED
     */
    INT32 disp_flag = (INT32)((INT64)(s_caveVA + CAVE_OFF_ENABLED)
                              - (INT64)(scBaseVA + off + 8));
    sc[off++]=0x48; sc[off++]=0x83; sc[off++]=0x3D;
    *(INT32*)(&sc[off]) = disp_flag; off+=4;
    sc[off++]=0x00;

    /* jz <to_ret> — patch offset later */
    int jz_off = off;
    sc[off++]=0x74; sc[off++]=0x00; /* placeholder */

    /* --- save regs --- */
    sc[off++]=0x57;             /* push rdi */
    sc[off++]=0x51;             /* push rcx */
    sc[off++]=0x52;             /* push rdx */
    sc[off++]=0x41; sc[off++]=0x50; /* push r8  */
    sc[off++]=0x41; sc[off++]=0x51; /* push r9  */
    sc[off++]=0x41; sc[off++]=0x52; /* push r10 */
    sc[off++]=0x41; sc[off++]=0x53; /* push r11 */
    sc[off++]=0x48; sc[off++]=0x83; sc[off++]=0xEC; sc[off++]=0x28; /* sub rsp, 0x28 */

    /* Stack layout after sub rsp,0x28:
     *  [rsp+0x00..0x27] = shadow space
     *  [rsp+0x28] = r11
     *  [rsp+0x30] = r10
     *  [rsp+0x38] = r9
     *  [rsp+0x40] = r8
     *  [rsp+0x48] = rdx (ammo enc value before we read it)
     *  [rsp+0x50] = rcx
     *  [rsp+0x58] = rdi   ← we need this to write back
     */

    /* mov edx, [rdi+0x2D9C]   ; edx = ammo_encrypted */
    /* 8B 97 9C 2D 00 00 */
    sc[off++]=0x8B; sc[off++]=0x97; sc[off++]=0x9C; sc[off++]=0x2D; sc[off++]=0x00; sc[off++]=0x00;

    /* mov rax, [rip+disp_key]  ; load get_ammo_key fn ptr
     * Instruction is 7 bytes: 48 8B 05 <disp32>
     * RIP after = scBaseVA + off + 7
     * target = caveVA + CAVE_OFF_GETKEY
     */
    INT32 disp_key = (INT32)((INT64)(s_caveVA + CAVE_OFF_GETKEY)
                              - (INT64)(scBaseVA + off + 7));
    sc[off++]=0x48; sc[off++]=0x8B; sc[off++]=0x05;
    *(INT32*)(&sc[off]) = disp_key; off+=4;

    /* call rax */
    sc[off++]=0xFF; sc[off++]=0xD0;

    /* mov ecx, eax   ; ecx = key  (89 C1) */
    sc[off++]=0x89; sc[off++]=0xC1;

    /* xor eax, edx   ; eax = raw = enc XOR key  (33 C2) */
    sc[off++]=0x33; sc[off++]=0xC2;

    /* mov r8d, dword [rip+disp_val]   ; 44 8B 05 <disp32>
     * RIP after = scBaseVA + off + 7
     * target = caveVA + CAVE_OFF_VALUE
     */
    INT32 disp_val = (INT32)((INT64)(s_caveVA + CAVE_OFF_VALUE)
                             - (INT64)(scBaseVA + off + 7));
    sc[off++]=0x44; sc[off++]=0x8B; sc[off++]=0x05;
    *(INT32*)(&sc[off]) = disp_val; off+=4;

    /* test r8d, r8d  ; (45 85 C0) */
    sc[off++]=0x45; sc[off++]=0x85; sc[off++]=0xC0;

    /* jz use_increment ; (74 05) - jumps 5 bytes over mov + jmp */
    sc[off++]=0x74; sc[off++]=0x05;

    /* mov eax, r8d   ; (41 89 C0) - 3 bytes */
    sc[off++]=0x41; sc[off++]=0x89; sc[off++]=0xC0;

    /* jmp start_crypto ; (EB 02) - 2 bytes */
    sc[off++]=0xEB; sc[off++]=0x02;

    /* use_increment: inc eax ; (FF C0) - 2 bytes */
    sc[off++]=0xFF; sc[off++]=0xC0;

    /* start_crypto: */

    /* ── GetEncryptedAmmo(eax) state machine ───────────────────────────── */
    /* ebx = eax (input = raw+1 or custom value) */
    sc[off++]=0x89; sc[off++]=0xC3;   /* mov ebx, eax */

    /* Step 1: eax = ebx ^ 0xF9DB */
    sc[off++]=0x89; sc[off++]=0xD8;   /* mov eax, ebx */
    sc[off++]=0x35; sc[off++]=0xDB; sc[off++]=0xF9; sc[off++]=0x00; sc[off++]=0x00; /* xor eax, 0xF9DB */

    /* Step 2: edx = (ebx & 0xFFFF) << 16 */
    sc[off++]=0x89; sc[off++]=0xDA;   /* mov edx, ebx */
    sc[off++]=0x81; sc[off++]=0xE2; sc[off++]=0xFF; sc[off++]=0xFF; sc[off++]=0x00; sc[off++]=0x00; /* and edx, 0xFFFF */
    sc[off++]=0xC1; sc[off++]=0xE2; sc[off++]=0x10; /* shl edx, 16 */

    /* Step 3: ebx = (ebx >> 16) | edx = ROL(ebx, 16) */
    sc[off++]=0xC1; sc[off++]=0xEB; sc[off++]=0x10; /* shr ebx, 16 */
    sc[off++]=0x09; sc[off++]=0xD3;                  /* or  ebx, edx */

    /* Step 4: ebx ^= eax */
    sc[off++]=0x31; sc[off++]=0xC3;   /* xor ebx, eax */

    /* Step 5: eax = (ebx ^ 0x0762) & 0xFFFF  (movzx) */
    sc[off++]=0x89; sc[off++]=0xD8;   /* mov eax, ebx */
    sc[off++]=0x35; sc[off++]=0x62; sc[off++]=0x07; sc[off++]=0x00; sc[off++]=0x00; /* xor eax, 0x762 */
    sc[off++]=0x0F; sc[off++]=0xB7; sc[off++]=0xC0; /* movzx eax, ax */

    /* Step 6: ebx = ROR(ebx,16) ^ eax */
    sc[off++]=0xC1; sc[off++]=0xCB; sc[off++]=0x10; /* ror ebx, 16 */
    sc[off++]=0x31; sc[off++]=0xC3;                  /* xor ebx, eax */

    /* Step 7: eax = (ebx ^ 0x957C) & 0xFFFF */
    sc[off++]=0x89; sc[off++]=0xD8;   /* mov eax, ebx */
    sc[off++]=0x35; sc[off++]=0x7C; sc[off++]=0x95; sc[off++]=0x00; sc[off++]=0x00; /* xor eax, 0x957C */
    sc[off++]=0x0F; sc[off++]=0xB7; sc[off++]=0xC0; /* movzx eax, ax */

    /* Step 8: ebx = ROL(ebx,16) ^ eax */
    sc[off++]=0xC1; sc[off++]=0xC3; sc[off++]=0x10; /* rol ebx, 16 */
    sc[off++]=0x31; sc[off++]=0xC3;                  /* xor ebx, eax */

    /* Step 9: eax = (ebx ^ 0x367E) & 0xFFFF */
    sc[off++]=0x89; sc[off++]=0xD8;   /* mov eax, ebx */
    sc[off++]=0x35; sc[off++]=0x7E; sc[off++]=0x36; sc[off++]=0x00; sc[off++]=0x00; /* xor eax, 0x367E */
    sc[off++]=0x0F; sc[off++]=0xB7; sc[off++]=0xC0; /* movzx eax, ax */

    /* Step 10: ebx = ROL(ebx,16) ^ eax */
    sc[off++]=0xC1; sc[off++]=0xC3; sc[off++]=0x10; /* rol ebx, 16 */
    sc[off++]=0x31; sc[off++]=0xC3;                  /* xor ebx, eax */

    /* Step 11: ebx = ROL(ebx,16) */
    sc[off++]=0xC1; sc[off++]=0xC3; sc[off++]=0x10; /* rol ebx, 16 */

    /* Apply key: ebx = sm_result XOR key (ecx=key from before call) */
    sc[off++]=0x31; sc[off++]=0xCB;   /* xor ebx, ecx */

    /* Reload rdi from stack (was pushed 7th, above sub rsp,28):
     * Stack: [rsp+0x58] = rdi
     */
    sc[off++]=0x48; sc[off++]=0x8B; sc[off++]=0xBC; sc[off++]=0x24;
    sc[off++]=0x58; sc[off++]=0x00; sc[off++]=0x00; sc[off++]=0x00; /* mov rdi, [rsp+0x58] */

    /* Write encrypted ammo: [rdi+0x2D9C] = ebx */
    sc[off++]=0x89; sc[off++]=0x9F; sc[off++]=0x9C; sc[off++]=0x2D; sc[off++]=0x00; sc[off++]=0x00;

    /* --- restore regs --- */
    sc[off++]=0x48; sc[off++]=0x83; sc[off++]=0xC4; sc[off++]=0x28; /* add rsp, 0x28 */
    sc[off++]=0x41; sc[off++]=0x5B; /* pop r11 */
    sc[off++]=0x41; sc[off++]=0x5A; /* pop r10 */
    sc[off++]=0x41; sc[off++]=0x59; /* pop r9  */
    sc[off++]=0x41; sc[off++]=0x58; /* pop r8  */
    sc[off++]=0x5A;                  /* pop rdx */
    sc[off++]=0x59;                  /* pop rcx */
    sc[off++]=0x5F;                  /* pop rdi */

    /* Patch jz offset: target = here (skip work if disabled) */
    sc[jz_off + 1] = (UINT8)(off - (jz_off + 2));

    UINT32 scLen = (UINT32)off;
    DEBUG_FLY("Ammo shellcode: %u bytes, jz_off=%d jz_rel=%d",
              scLen, jz_off, (int)sc[jz_off+1]);

    /* Pass caveVA+CAVE_OFF_SC to LazyHook */
    s_hookId = LazyHook_Install(
        cr3,
        hookVA, AMMO_STOLEN_LEN,
        sc, scLen,
        scBaseVA);

    DEBUG_FLY("Ammo: LazyHook_Install -> hookId=%d", s_hookId);
    return (s_hookId >= 0);
}

/* ── Public API ───────────────────────────────────────────────────────── */

void Ammo_OnAttach(void)
{
    s_enabled  = FALSE;
    s_hookId   = -1;
    s_hookVA   = 0;
    s_caveVA   = 0;
    s_caveSize = 0;
    s_getKeyVA = 0;

    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    DEBUG_FLY("=== Ammo_OnAttach: cr3=0x%I64X base=0x%I64X ===", cr3, d2Base);
    if (!cr3 || !d2Base) return;

    s_getKeyVA = d2Base + SecureReadStatic(&OBF_OFF_GetKeyVA);
    DEBUG_FLY("Ammo_OnAttach: get_ammo_key VA=0x%I64X (Secure)", s_getKeyVA);

    FindAmmoCave(cr3, d2Base);
    InstallAmmoHook(cr3, d2Base);
}

void Ammo_SetEnabled(BOOL en)
{
    DEBUG_FLY("Ammo_SetEnabled: %s (hookId=%d, caveVA=0x%I64X)", en ? "ON" : "OFF", s_hookId, s_caveVA);
    s_enabled = en;

    if (!s_caveVA) {
        DEBUG_FLY("Ammo_SetEnabled: cave not ready, flag cached only");
        return;
    }
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 flag = en ? 1ULL : 0ULL;
    BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_ENABLED, &flag, 8);
}

BOOL Ammo_IsEnabled(void) { return s_enabled; }

UINT64 Ammo_GetCaveVA(void) { return s_caveVA; }

void Ammo_SetValue(UINT32 val)
{
    s_customVal = val;
    if (!s_caveVA) return;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_VALUE, &s_customVal, 4);
    BYOVD_UNLOCK();
}

UINT32 Ammo_GetValue(void)
{
    return s_customVal;
}

/* Tick: refresh the enabled flag each frame in case CR3 changed */
void Ammo_Tick(void)
{
    if (!s_caveVA || s_hookId < 0) return;

    static DWORD s_lastTick = 0;
    DWORD now = GetTickCount();
    if (now - s_lastTick < AMMO_TICK_MS) return;
    s_lastTick = now;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    BYOVD_LOCK();
    UINT64 flag = s_enabled ? 1ULL : 0ULL;
    BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_ENABLED, &flag, 8);
    BYOVD_WriteVA(cr3, s_caveVA + CAVE_OFF_VALUE, &s_customVal, 4);
    BYOVD_UNLOCK();
}

void Ammo_OnDetach(void)
{
    DEBUG_FLY("=== Ammo_OnDetach ===");
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId >= 0 && cr3)
        LazyHook_Remove(s_hookId, cr3);
    s_hookId   = -1;
    s_hookVA   = 0;
    s_caveVA   = 0;
    s_getKeyVA = 0;
    s_enabled  = FALSE;
    s_customVal = 0;
}

UINT64 Ammo_GetGetKeyVA(void)
{
    return s_getKeyVA;
}
#endif
