/* namechanger.c
 *
 * New Tiger-based approach. 
 * Replaces the previous AOB bypass with 3 inline hooks in the game process:
 * 1. NameBufGetterFn
 * 2. NameCopy66Fn
 * 3. NameDecodeFn
 */

#include "namechanger.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "cave_finder.h"
#include "attach.h"
#include "debug.h"
#include "gui_core.h"
#include <windows.h>
#include "aob_patterns.h"
#include <string.h>
#include <stdint.h>

static BOOL   s_enabled   = FALSE;
static char   s_name[64]  = {0};
static BOOL   s_nameDirty = FALSE;

static UINT64 s_caveVA          = 0;
static BOOL   s_hooked          = FALSE;

static UINT64 s_getterCallSite = 0;
static UINT64 s_copyCallSite   = 0;
static UINT64 s_decodeCallSite = 0;

static INT32  s_origGetterRel  = 0;
static INT32  s_origCopyRel    = 0;
static INT32  s_origDecodeRel  = 0;



#define NAME_XOR_KEY  0x7A136D5EUL
#define NAME_MULT     91u

static inline uint32_t rol32(uint32_t v, int n){ return (v<<n)|(v>>(32-n)); }

#include "xor_strings.h"

static BOOL InstallHooks(UINT64 cr3, UINT64 d2Base)
{
    /* Find the 3 call instructions using SecureReadStatic */
    UINT64 getterCall = d2Base + SecureReadStatic(&OBF_OFF_NC_GetterCall);
    UINT64 copyCall   = d2Base + SecureReadStatic(&OBF_OFF_NC_CopyCall);
    UINT64 decodeCall = d2Base + SecureReadStatic(&OBF_OFF_NC_DecodeCall);

    s_getterCallSite = getterCall;
    s_copyCallSite   = copyCall;
    s_decodeCallSite = decodeCall;

    /* Read and save original relative offsets from the call sites (E8 + 1) */
    BYOVD_ReadVA(cr3, getterCall + 1, &s_origGetterRel, 4);
    BYOVD_ReadVA(cr3, copyCall + 1,   &s_origCopyRel,   4);
    BYOVD_ReadVA(cr3, decodeCall + 1, &s_origDecodeRel, 4);

    /* Resolve original function VAs: Caller site address + instruction size (5 bytes) + displacement offset */
    UINT64 origGetterVA = getterCall + 5 + (INT64)s_origGetterRel;
    UINT64 origCopyVA   = copyCall + 5 + (INT64)s_origCopyRel;
    UINT64 origDecodeVA = decodeCall + 5 + (INT64)s_origDecodeRel;

    DEBUG_NC("Hooks resolved. Getter:%I64X Copy:%I64X Decode:%I64X", origGetterVA, origCopyVA, origDecodeVA);

    /* Allocate cave (min 448 bytes for layout + 3 shellcodes) */
    s_caveVA = CaveFinder_FindNear(cr3, d2Base, 448, getterCall);
    if (!s_caveVA) {
        DEBUG_NC("Hook: No cave found.");
        return FALSE;
    }
    
    DEBUG_NC("Hook: Cave allocated at %I64X", s_caveVA);

    /* Cave Layout:
       +0x00 : Mailbox (RealNameBufPtr) (8 bytes)
       +0x08 : IsEnabled flag (4 bytes)
       +0x10 : SpoofedNameBuffer (80 bytes: 64 name + 8 padding + 8 hash)
       +0x80 : Getter Hook Shellcode
       +0xC0 : Copy Hook Shellcode
       +0x100: Decode Hook Shellcode
    */
    UINT64 mailboxVA  = s_caveVA + 0x00;
    UINT64 enabledVA  = s_caveVA + 0x08;
    UINT64 spoofVA    = s_caveVA + 0x10;
    
    UINT64 shGetterVA = s_caveVA + 0x80;
    UINT64 shCopyVA   = s_caveVA + 0xC0;
    UINT64 shDecodeVA = s_caveVA + 0x100;

    /* Construct Getter Shellcode (62 bytes) */
    UINT8 scGetter[64];
    memset(scGetter, 0, sizeof(scGetter));
    int p = 0;
    scGetter[p++] = 0x51;                                      // push rcx
    scGetter[p++] = 0x48; scGetter[p++] = 0x83; scGetter[p++] = 0xEC; scGetter[p++] = 0x20; // sub rsp, 32
    scGetter[p++] = 0x48; scGetter[p++] = 0xB8; memcpy(&scGetter[p], &origGetterVA, 8); p += 8; // mov rax, <orig_getter>
    scGetter[p++] = 0xFF; scGetter[p++] = 0xD0;                // call rax
    scGetter[p++] = 0x48; scGetter[p++] = 0x83; scGetter[p++] = 0xC4; scGetter[p++] = 0x20; // add rsp, 32
    scGetter[p++] = 0x59;                                      // pop rcx
    scGetter[p++] = 0x48; scGetter[p++] = 0xB9; memcpy(&scGetter[p], &mailboxVA, 8); p += 8;    // mov rcx, <mailbox>
    scGetter[p++] = 0x48; scGetter[p++] = 0x89; scGetter[p++] = 0x01;  // mov [rcx], rax
    scGetter[p++] = 0x48; scGetter[p++] = 0xB9; memcpy(&scGetter[p], &enabledVA, 8); p += 8;    // mov rcx, <enabled>
    scGetter[p++] = 0x8B; scGetter[p++] = 0x09;                // mov ecx, [rcx]
    scGetter[p++] = 0x85; scGetter[p++] = 0xC9;                // test ecx, ecx
    scGetter[p++] = 0x74; scGetter[p++] = 0x0A;                // jz exit (10 bytes forward)
    scGetter[p++] = 0x48; scGetter[p++] = 0xB8; memcpy(&scGetter[p], &spoofVA, 8); p += 8;      // mov rax, <spoof_buf>
    scGetter[p++] = 0xC3;                                      // ret

    /* Construct Copy Shellcode (58 bytes) */
    UINT8 scCopy[64];
    memset(scCopy, 0, sizeof(scCopy));
    p = 0;
    scCopy[p++] = 0x48; scCopy[p++] = 0xB8; memcpy(&scCopy[p], &enabledVA, 8); p += 8;    // mov rax, <enabled>
    scCopy[p++] = 0x8B; scCopy[p++] = 0x00;                      // mov eax, [rax]
    scCopy[p++] = 0x85; scCopy[p++] = 0xC0;                      // test eax, eax
    scCopy[p++] = 0x74; scCopy[p++] = 0x1C;                      // jz call_orig (28 bytes forward)
    scCopy[p++] = 0x48; scCopy[p++] = 0xB8; memcpy(&scCopy[p], &mailboxVA, 8); p += 8;    // mov rax, <mailbox>
    scCopy[p++] = 0x48; scCopy[p++] = 0x8B; scCopy[p++] = 0x00;  // mov rax, [rax]
    scCopy[p++] = 0x48; scCopy[p++] = 0x39; scCopy[p++] = 0xC2;  // cmp rdx, rax
    scCopy[p++] = 0x75; scCopy[p++] = 0x0A;                      // jne call_orig (10 bytes forward)
    scCopy[p++] = 0x48; scCopy[p++] = 0xBA; memcpy(&scCopy[p], &spoofVA, 8); p += 8;      // mov rdx, <spoof_buf>
    // call_orig:
    scCopy[p++] = 0x48; scCopy[p++] = 0xB8; memcpy(&scCopy[p], &origCopyVA, 8); p += 8;  // mov rax, <orig_copy>
    scCopy[p++] = 0xFF; scCopy[p++] = 0xE0;                      // jmp rax

    /* Construct Decode Shellcode (58 bytes) */
    UINT8 scDecode[64];
    memset(scDecode, 0, sizeof(scDecode));
    p = 0;
    scDecode[p++] = 0x48; scDecode[p++] = 0xB8; memcpy(&scDecode[p], &enabledVA, 8); p += 8;    // mov rax, <enabled>
    scDecode[p++] = 0x8B; scDecode[p++] = 0x00;                      // mov eax, [rax]
    scDecode[p++] = 0x85; scDecode[p++] = 0xC0;                      // test eax, eax
    scDecode[p++] = 0x74; scDecode[p++] = 0x1C;                      // jz call_orig (28 bytes forward)
    scDecode[p++] = 0x48; scDecode[p++] = 0xB8; memcpy(&scDecode[p], &mailboxVA, 8); p += 8;    // mov rax, <mailbox>
    scDecode[p++] = 0x48; scDecode[p++] = 0x8B; scDecode[p++] = 0x00;  // mov rax, [rax]
    scDecode[p++] = 0x48; scDecode[p++] = 0x39; scDecode[p++] = 0xC2;  // cmp rdx, rax
    scDecode[p++] = 0x75; scDecode[p++] = 0x0A;                      // jne call_orig (10 bytes forward)
    scDecode[p++] = 0x48; scDecode[p++] = 0xBA; memcpy(&scDecode[p], &spoofVA, 8); p += 8;      // mov rdx, <spoof_buf>
    // call_orig:
    scDecode[p++] = 0x48; scDecode[p++] = 0xB8; memcpy(&scDecode[p], &origDecodeVA, 8); p += 8;  // mov rax, <orig_decode>
    scDecode[p++] = 0xFF; scDecode[p++] = 0xE0;                      // jmp rax

    /* Write everything to the remote cave */
    BYOVD_SetPageWritable(cr3, s_caveVA);
    
    // Clear mailbox and enabled flag initially
    UINT64 zero = 0;
    BYOVD_WriteVA(cr3, mailboxVA, &zero, 8);
    UINT32 enabledState = s_enabled ? 1 : 0;
    BYOVD_WriteVA(cr3, enabledVA, &enabledState, 4);
    
    // Write shellcodes
    BYOVD_WriteVA(cr3, shGetterVA, scGetter, 64);
    BYOVD_WriteVA(cr3, shCopyVA,   scCopy,   64);
    BYOVD_WriteVA(cr3, shDecodeVA, scDecode, 64);

    /* Redirect the original call sites to our shellcodes */
    INT32 newRelGetter = (INT32)(shGetterVA - (getterCall + 5));
    INT32 newRelCopy   = (INT32)(shCopyVA - (copyCall + 5));
    INT32 newRelDecode = (INT32)(shDecodeVA - (decodeCall + 5));

    BYOVD_WriteVA(cr3, getterCall + 1, &newRelGetter, 4);
    BYOVD_WriteVA(cr3, copyCall + 1,   &newRelCopy,   4);
    BYOVD_WriteVA(cr3, decodeCall + 1, &newRelDecode, 4);

    DEBUG_NC("Hooks installed successfully. Cave: %I64X", s_caveVA);
    return TRUE;
}

void NameChanger_OnAttach(void)
{
    s_enabled = FALSE; s_nameDirty = FALSE;
    s_caveVA = 0; s_hooked = FALSE;
    s_getterCallSite = 0; s_copyCallSite = 0; s_decodeCallSite = 0;
    s_origGetterRel = 0; s_origCopyRel = 0; s_origDecodeRel = 0;
}

void NameChanger_OnDetach(void)
{
    if (s_hooked && s_caveVA) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            BYOVD_LOCK();
            /* Restore original call site offsets */
            BYOVD_WriteVA(cr3, s_getterCallSite + 1, &s_origGetterRel, 4);
            BYOVD_WriteVA(cr3, s_copyCallSite + 1,   &s_origCopyRel,   4);
            BYOVD_WriteVA(cr3, s_decodeCallSite + 1, &s_origDecodeRel, 4);
            BYOVD_UNLOCK();
        }
        s_hooked = FALSE;
    }
    NameChanger_SetEnabled(FALSE);
}

void NameChanger_SetName(const char *name)
{
    if (name && name[0]) {
        strncpy(s_name, name, 63); s_name[63]='\0';
        s_nameDirty = TRUE;
        DEBUG_NC("SetName: [%s]", s_name);
    }
}

void NameChanger_SetEnabled(BOOL en)
{
    if (en == s_enabled) return;
    s_enabled = en;
    if (en) { s_nameDirty = TRUE; }
    
    if (s_hooked && s_caveVA) {
        UINT64 cr3 = GetDestiny2CR3();
        if (cr3) {
            UINT32 e = en ? 1 : 0;
            BYOVD_WriteVA_Fresh(cr3, s_caveVA + 0x08, &e, 4);
        }
    }
}

BOOL NameChanger_IsEnabled(void) { return s_enabled; }
BOOL NameChanger_IsReady(void)   { return s_hooked; }

void NameChanger_Tick(void)
{
    if (!s_enabled || !s_nameDirty) return;

    UINT64 cr3  = GetDestiny2CR3();
    UINT64 base = (UINT64)GetDestiny2Base();
    if (!cr3 || !base) return;

    if (!s_hooked) {
        if (!BYOVD_TRYLOCK()) return;
        BOOL ok = InstallHooks(cr3, base);
        BYOVD_UNLOCK();
        if (!ok) return;
        s_hooked = TRUE;
    }

    size_t len = strlen(s_name);
    if (len > 63) len = 63;

    /* Build SpoofedNameBuffer: encrypted name (64 bytes) + padding (8 bytes) + hash (8 bytes) */
    UINT8 buffer[80];
    memset(buffer, 0, sizeof(buffer));

    // Copy plain text to initial bytes first, then encrypt in place
    memcpy(buffer, s_name, len);

    for (size_t i = 0; i < len; i++) {
        uint8_t key = (i > 0) ? (uint8_t)rol32(NAME_XOR_KEY, (int)(i % 31)) : 0;
        buffer[i] = (uint8_t)(NAME_MULT * (uint8_t)s_name[i]) ^ key;
    }

    // Compute FNV-1a hash of the encrypted bytes
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; i++) {
        hash *= 0x100000001B3ULL;
        hash ^= buffer[i];
    }
    
    // Write FNV-1a hash at offset +72 (which is index 72 to 79 of buffer)
    memcpy(&buffer[72], &hash, 8);

    if (!BYOVD_TRYLOCK()) return;
    BYOVD_WriteVA(cr3, s_caveVA + 0x10, buffer, 80);
    BYOVD_UNLOCK();

    s_nameDirty = FALSE;
}
