/*
 * sobject_list.c  --  SObject List reading and resolution (Internal build only)
 */
#if !defined(SERAPH_DMA_BUILD) && !defined(SERAPH_EXTERNAL_BUILD)

/*=============================================================================
 * sobject_list.c — SObject World Entity List implementation
 *
 * LOGGING: ALL operations log unconditionally to %USERPROFILE%\Downloads\
 * seraph_sobject.log for full diagnostics.
 *===========================================================================*/

#include "sobject_list.h"
#include "esp.h"          /* for ESP_DecryptPtr, g_EspState */
#include "debug.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * UNCONDITIONAL LOGGING — always writes to Downloads\seraph_sobject.log
 * ═══════════════════════════════════════════════════════════════════════════ */

static char g_logBuf[2048];
static BOOL g_logCreated = FALSE;

/* ── creates the log file with a header on first call ───────────────────── */
static void _Log(const char *fmt, ...)
{
#ifdef NDEBUG
    (void)fmt;
    return;
#else
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH - 32);
    if (!n || n >= MAX_PATH - 32) return;
    lstrcatA(path, "\\Downloads\\seraph_sobject.log");

    /* On first call: create file with header, overwriting any previous */
    if (!g_logCreated) {
        g_logCreated = TRUE;
        HANDLE hC = CreateFileA(path, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hC != INVALID_HANDLE_VALUE) {
            char hdr[256];
            int hl = wsprintfA(hdr, "=== SObject List Log ===\r\nCreated: %lu\r\n\r\n", GetTickCount());
            DWORD w; WriteFile(hC, hdr, hl, &w, NULL);
            CloseHandle(hC);
        }
    }

    va_list args;
    va_start(args, fmt);
    int len = wsprintfA(g_logBuf, "[SOBJ] ");
    len += wvsprintfA(g_logBuf + len, fmt, args);
    va_end(args);

    /* Ensure CRLF termination */
    int slen = lstrlenA(g_logBuf);
    if (slen + 3 < (int)sizeof(g_logBuf)) {
        g_logBuf[slen] = '\r';
        g_logBuf[slen+1] = '\n';
        g_logBuf[slen+2] = '\0';
    }

    HANDLE hF = CreateFileA(path, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) return;
    DWORD w;
    WriteFile(hF, g_logBuf, (DWORD)lstrlenA(g_logBuf), &w, NULL);
    CloseHandle(hF);
#endif
}

/* ── Rotate helpers for decryption ───────────────────────────────────────── */
static __inline uint32_t _rol32(uint32_t v, int n) {
    n &= 31;
    return n ? ((v << n) | (v >> (32 - n))) : v;
}
static __inline uint32_t _ror32(uint32_t v, int n) {
    n &= 31;
    return n ? ((v >> n) | (v << (32 - n))) : v;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * POSITION DECRYPTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_DecryptPosFloat ──────────────────────────────────────────── *
 * Direct C port of the cff_decrypt_float state machine.
 * This is a DIFFERENT key4 from the HP decryption!                          */
float SObjectList_DecryptPosFloat(uint32_t encrypted, uint32_t key4)
{
    uint32_t ebx = encrypted;
    uint32_t ecx = 0x4393ADDDu;
    uint32_t edx = 0;

    for (int guard = 0; guard < 64; guard++) {
        if (ecx == 0xD255BB56u) {
            ebx ^= edx;
            ebx  = _rol32(ebx, 16);
            ebx ^= key4;
            float result;
            memcpy(&result, &ebx, 4);
            _Log("DecryptPosFloat: enc=0x%08X key4=0x%08X result=%f (raw=0x%08X)",
                encrypted, key4, result, ebx);
            return result;
        }

        uint32_t eax;
        switch (ecx) {
            case 0x4393ADDDu:
                eax = 0xAB984326u;
                edx = (uint32_t)(uint16_t)ebx;
                break;
            case 0x059FCC87u:
                eax = 0x91CF90BCu;
                ebx = _rol32(ebx, 16);
                edx = (uint32_t)(uint16_t)(ebx ^ 0x5340u);
                break;
            case 0xCCD630EDu:
                edx ^= 0x4AC5u;
                eax = 0x1E838BBBu;
                ebx = _ror32(ebx, 16);
                break;
            case 0xE80BEEFBu:
                edx ^= 0x9DE8u;
                eax = 0x1CF9DC4Eu;
                ebx = _ror32(ebx, 16);
                break;
            case 0xFB91CDDAu:
                edx = (uint32_t)(uint16_t)(ebx ^ 0xFFFF89C6u);
                eax = 0x7FBB741Au;
                ebx = _rol32(ebx, 16);
                break;
            case 0xF4F232B5u:
                ebx ^= edx;
                eax = 0x05569343u;
                break;
            case 0xF1A4A1F6u:
                eax = 0x3D72911Bu;
                edx = (uint32_t)(uint16_t)ebx;
                break;
            default:
                _Log("DecryptPosFloat: UNKNOWN state ecx=0x%08X at guard=%d", ecx, guard);
                return 0.0f;
        }
        ecx ^= eax;
    }
    _Log("DecryptPosFloat: guard EXCEEDED (64 iterations) for enc=0x%08X", encrypted);
    return 0.0f;
}

/* ── SObjectList_DecryptPosition ──────────────────────────────────────────── */
BOOL SObjectList_DecryptPosition(const float enc_xyz[3], uint32_t key4,
                                 float out_xyz[3])
{
    if (!enc_xyz || !out_xyz) {
        _Log("DecryptPosition: NULL pointer");
        return FALSE;
    }

    uint32_t k = key4;
    if (k == 0 && g_EspState.keys_valid) {
        k = g_EspState.key4;
        _Log("DecryptPosition: key4 was 0, using HP key4=0x%08X", k);
    }
    if (k == 0) {
        _Log("DecryptPosition: no key4 available (key4=0, keys_valid=%d)", (int)g_EspState.keys_valid);
        return FALSE;
    }

    uint32_t raw[3];
    memcpy(&raw[0], &enc_xyz[0], 4);
    memcpy(&raw[1], &enc_xyz[1], 4);
    memcpy(&raw[2], &enc_xyz[2], 4);

    _Log("DecryptPosition: enc_raw=[0x%08X 0x%08X 0x%08X] key4=0x%08X",
        raw[0], raw[1], raw[2], k);

    for (int i = 0; i < 3; i++) {
        out_xyz[i] = SObjectList_DecryptPosFloat(raw[i], k);
    }

    _Log("DecryptPosition: decrypted=[%f %f %f]", out_xyz[0], out_xyz[1], out_xyz[2]);
    return TRUE;
}

/* SObjectList_ScanPosKey4 replaced with dynamic synchronization from g_EspState.key4. */

/* ── Module state ────────────────────────────────────────────────────────── */
static SObjectListState s_state = { 0 };
SObjectListState g_sobjState = { 0 };

/* ── RIP-relative address resolver ───────────────────────────────────────── */
static UINT64 _ResolveRIP(UINT64 instr_va, int disp_off, int instr_len)
{
    INT32 disp = 0;
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ResolveRIP: no CR3 for 0x%I64X", instr_va);
        return 0;
    }
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, instr_va + disp_off, &disp, 4);
    BYOVD_UNLOCK();
    if (!ok) {
        _Log("ResolveRIP: read failed at 0x%I64X +%d", instr_va, disp_off);
        return 0;
    }
    UINT64 result = instr_va + instr_len + (INT64)disp;
    _Log("ResolveRIP: addr=0x%I64X disp=%d (0x%X) len=%d -> 0x%I64X",
        instr_va, disp, (unsigned)disp, instr_len, result);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AOB SCANS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── Scan entity loop AOB ────────────────────────────────────────────────── */
static BOOL _ScanEntityLoop(UINT64 d2Base)
{
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !d2Base) {
        _Log("ScanEntityLoop: skipped, cr3=0x%I64X base=0x%I64X", cr3, d2Base);
        return FALSE;
    }

    _Log("ScanEntityLoop: scanning AOB (len=%u) in .text from 0x%I64X",
        SOBJ_AOB_ENTITY_LOOP_LEN, d2Base);

    UINT64 match = BYOVD_ScanPatternText(cr3, d2Base,
        (const UINT8*)SOBJ_AOB_ENTITY_LOOP,
        (const UINT8*)SOBJ_MASK_ENTITY_LOOP,
        SOBJ_AOB_ENTITY_LOOP_LEN);

    if (!match) {
        _Log("ScanEntityLoop: AOB NOT FOUND");
        return FALSE;
    }

    _Log("ScanEntityLoop: AOB match at 0x%I64X", match);

    /* Dump raw bytes at match for verification */
    UINT8 raw[28];
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, match, raw, sizeof(raw));
    BYOVD_UNLOCK();
    {
        char hex[96] = "";
        int pos = 0;
        for (int i = 0; i < 28 && pos < 90; i++) {
            pos += wsprintfA(hex + pos, "%02X ", raw[i]);
        }
        _Log("ScanEntityLoop: raw bytes: %s", hex);
    }

    /* Resolve TigerListBase from 48 8B 05 ?? ?? ?? ?? at match[0..6] */
    UINT64 base_ptr_va = _ResolveRIP(match, 3, 7);
    if (!base_ptr_va) {
        _Log("ScanEntityLoop: base_ptr RIP-resolve failed");
        return FALSE;
    }

    /* Read the actual base pointer */
    UINT64 base = 0;
    BYOVD_LOCK();
    BOOL read_ok = BYOVD_ReadVA(cr3, base_ptr_va, &base, 8);
    BYOVD_UNLOCK();

    if (!read_ok) {
        _Log("ScanEntityLoop: failed to read base at 0x%I64X", base_ptr_va);
        return FALSE;
    }

    _Log("ScanEntityLoop: base_ptr_va=0x%I64X base_value=0x%I64X", base_ptr_va, base);

    if (!base || base < 0x100000000ULL) {
        _Log("ScanEntityLoop: base 0x%I64X is INVALID (must be >= 0x100000000)", base);
        return FALSE;
    }

    /* Resolve stride from 0F AF 0D ?? ?? ?? ?? at match[13..19] */
    UINT64 stride_ptr_va = _ResolveRIP(match, 16, 7);
    if (stride_ptr_va) {
        UINT32 stride_val = 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, stride_ptr_va, &stride_val, 4);
        BYOVD_UNLOCK();
        s_state.stride = stride_val;
        _Log("ScanEntityLoop: stride=0x%X (%u)", stride_val, stride_val);
    } else {
        s_state.stride = SOBJ_STRIDE;
        _Log("ScanEntityLoop: stride RIP-resolve failed, using hardcoded 0x%X (224)", (unsigned)SOBJ_STRIDE);
    }

    s_state.tiger_list_base = base;
    s_state.has_static_base = TRUE;

    _Log("ScanEntityLoop: SUCCESS base=0x%I64X stride=%I64u", base, s_state.stride);
    return TRUE;
}

/* ── Scan encrypted pointer AOB ──────────────────────────────────────────── */
static BOOL _ScanEncPtr(UINT64 d2Base)
{
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !d2Base) {
        _Log("ScanEncPtr: skipped, no cr3/base");
        return FALSE;
    }

    _Log("ScanEncPtr: scanning 4C 8B 15 AOB (len=%u)", SOBJ_AOB_ENC_PTR_LEN);

    UINT64 match = BYOVD_ScanPatternText(cr3, d2Base,
        (const UINT8*)SOBJ_AOB_ENC_PTR,
        (const UINT8*)SOBJ_MASK_ENC_PTR,
        SOBJ_AOB_ENC_PTR_LEN);

    if (!match) {
        _Log("ScanEncPtr: AOB NOT FOUND");
        return FALSE;
    }

    _Log("ScanEncPtr: AOB match at 0x%I64X", match);

    UINT64 enc_ptr_va = _ResolveRIP(match, 3, 7);
    if (!enc_ptr_va) {
        _Log("ScanEncPtr: RIP-resolve failed");
        return FALSE;
    }

    s_state.enc_ptr_va = enc_ptr_va;
    s_state.has_enc_ptr = TRUE;

    _Log("ScanEncPtr: enc_ptr_va=0x%I64X, attempting ESP_DecryptPtr", enc_ptr_va);

    UINT64 decrypted = ESP_DecryptPtr(cr3, enc_ptr_va);
    _Log("ScanEncPtr: decrypted=0x%I64X", decrypted);

    if (decrypted && decrypted > 0x100000000ULL) {
        s_state.enc_ptr_decrypted = decrypted;
        if (!s_state.has_static_base) {
            s_state.tiger_list_base = decrypted;
            s_state.has_static_base = TRUE;
            _Log("ScanEncPtr: using decrypted ptr as base=0x%I64X", decrypted);
        }
    } else {
        _Log("ScanEncPtr: decryption returned 0 or invalid pointer");
    }

    return TRUE;
}

/* ── Scan handle pool root AOB ───────────────────────────────────────────── */
static BOOL _ScanHandlePoolRoot(UINT64 d2Base)
{
    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3 || !d2Base) {
        _Log("ScanHandlePoolRoot: skipped");
        return FALSE;
    }

    _Log("ScanHandlePoolRoot: trying option 1 (len=%u)", SOBJ_AOB_POOL_ROOT_1_LEN);

    UINT64 match = BYOVD_ScanPatternText(cr3, d2Base,
        (const UINT8*)SOBJ_AOB_POOL_ROOT_1,
        (const UINT8*)SOBJ_MASK_POOL_ROOT_1,
        SOBJ_AOB_POOL_ROOT_1_LEN);

    if (!match) {
        _Log("ScanHandlePoolRoot: option 1 not found, trying option 2 (len=%u)",
            SOBJ_AOB_POOL_ROOT_2_LEN);
        match = BYOVD_ScanPatternText(cr3, d2Base,
            (const UINT8*)SOBJ_AOB_POOL_ROOT_2,
            (const UINT8*)SOBJ_MASK_POOL_ROOT_2,
            SOBJ_AOB_POOL_ROOT_2_LEN);
    }

    if (!match) {
        _Log("ScanHandlePoolRoot: neither AOB found");
        return FALSE;
    }

    _Log("ScanHandlePoolRoot: AOB match at 0x%I64X", match);

    UINT64 pool_root_ptr_va = _ResolveRIP(match, 3, 7);
    if (!pool_root_ptr_va) {
        _Log("ScanHandlePoolRoot: RIP-resolve failed");
        return FALSE;
    }

    UINT64 pool_root = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, pool_root_ptr_va, &pool_root, 8);
    BYOVD_UNLOCK();

    if (!ok) {
        _Log("ScanHandlePoolRoot: read failed at 0x%I64X", pool_root_ptr_va);
        return FALSE;
    }

    _Log("ScanHandlePoolRoot: ptr_va=0x%I64X pool_root=0x%I64X", pool_root_ptr_va, pool_root);

    if (!pool_root || pool_root < 0x100000000ULL) {
        _Log("ScanHandlePoolRoot: pool_root 0x%I64X is invalid", pool_root);
        return FALSE;
    }

    s_state.handle_pool_root = pool_root;
    s_state.has_pool_root = TRUE;

    _Log("ScanHandlePoolRoot: SUCCESS pool_root=0x%I64X", pool_root);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PUBLIC API
 * ═══════════════════════════════════════════════════════════════════════════ */

#include "xor_strings.h"

/* ── SObjectList_Init ─────────────────────────────────────────────────────── */
BOOL SObjectList_Init(void)
{
    _Log("=== SObjectList_Init ===");

    if (s_state.initialized) {
        _Log("Init: already initialized, returning cached state");
        return TRUE;
    }

    UINT64 d2Base = GetDestiny2Base();
    if (!d2Base) {
        _Log("Init: FAILED — no d2Base");
        return FALSE;
    }

    _Log("Init: d2Base=0x%I64X", d2Base);

    /* Sync datum table from ESP state */
    _Log("Init: ESP state — datum_valid=%d keys_valid=%d tl_valid=%d",
        (int)g_EspState.datum_valid,
        (int)g_EspState.keys_valid,
        (int)g_EspState.tl_valid);

    if (g_EspState.datum_valid) {
        s_state.datum_table_va = g_EspState.datum_table_va;
        s_state.datum_valid = TRUE;
        _Log("Init: datum_table_va=0x%I64X", g_EspState.datum_table_va);
    } else {
        _Log("Init: datum_table NOT valid yet (ESP_Init may not have run)");
    }

    /* Assign Static Base and Stride directly using secure compile-time offsets */
    s_state.tiger_list_base = d2Base + SecureReadStatic(&OBF_OFF_SObjectListBase);
    s_state.stride = SOBJ_STRIDE;
    s_state.has_static_base = TRUE;

    /* Assign Handle Pool Root directly using secure compile-time offset */
    s_state.handle_pool_root = d2Base + SecureReadStatic(&OBF_OFF_HandlePoolRoot);
    s_state.has_pool_root = TRUE;

    /* Position decryption key4 synchronized from g_EspState.key4 (K4 pair) */
    s_state.pos_key4 = g_EspState.key4;
    s_state.has_pos_key4 = (g_EspState.key4 != 0);
    _Log("Init: pos_key4 synced from g_EspState.key4 as 0x%08X", g_EspState.key4);

    s_state.initialized = s_state.has_static_base;
    _Log("Init: has_static_base=%d has_enc_ptr=%d has_pool_root=%d has_pos_key4=%d initialized=%d",
        (int)s_state.has_static_base,
        (int)s_state.has_enc_ptr,
        (int)s_state.has_pool_root,
        (int)s_state.has_pos_key4,
        (int)s_state.initialized);

    if (s_state.initialized) {
        _Log("Init: SUCCESS — tiger_list_base=0x%I64X stride=%I64u",
            s_state.tiger_list_base, s_state.stride);
    } else {
        _Log("Init: FAILED — no valid entity base resolved");
    }

    /* Sync to global state */
    g_sobjState = s_state;
    return s_state.initialized;
}

/* ── SObjectList_Reset ────────────────────────────────────────────────────── */
void SObjectList_Reset(void)
{
    _Log("=== SObjectList_Reset ===");
    _Log("Reset: clearing all state (was initialized=%d)", (int)s_state.initialized);
    memset(&s_state, 0, sizeof(s_state));
    memset(&g_sobjState, 0, sizeof(g_sobjState));
    _Log("Reset: done");
}

/* ── SObjectList_IsReady ──────────────────────────────────────────────────── */
BOOL SObjectList_IsReady(void)
{
    BOOL ready = s_state.initialized && s_state.has_static_base;
    _Log("IsReady: %s (init=%d base=%d base_va=0x%I64X)",
        ready ? "YES" : "NO",
        (int)s_state.initialized,
        (int)s_state.has_static_base,
        s_state.tiger_list_base);
    return ready;
}

/* ── SObjectList_GetArrayBase ─────────────────────────────────────────────── */
UINT64 SObjectList_GetArrayBase(void)
{
    if (!s_state.initialized) {
        _Log("GetArrayBase: returning 0 (not initialized)");
        return 0;
    }
    _Log("GetArrayBase: returning 0x%I64X", s_state.tiger_list_base);
    return s_state.tiger_list_base;
}

/* ── SObjectList_GetStride ────────────────────────────────────────────────── */
UINT64 SObjectList_GetStride(void)
{
    UINT64 st = s_state.stride ? s_state.stride : SOBJ_STRIDE;
    _Log("GetStride: returning %I64u (0x%I64X)", st, st);
    return st;
}

/* ── SObjectList_GetMaxCount ──────────────────────────────────────────────── */
UINT32 SObjectList_GetMaxCount(void)
{
    _Log("GetMaxCount: returning %u", (unsigned)SOBJ_MAX_COUNT);
    return SOBJ_MAX_COUNT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PER-ENTITY READS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_ReadEntity ───────────────────────────────────────────────── */
BOOL SObjectList_ReadEntity(UINT32 index, SObjectRaw *out)
{
    if (!out) {
        _Log("ReadEntity[%u]: NULL output pointer", (unsigned)index);
        return FALSE;
    }

    if (!s_state.initialized || !s_state.tiger_list_base) {
        _Log("ReadEntity[%u]: not initialized", (unsigned)index);
        return FALSE;
    }

    if (index >= SOBJ_MAX_COUNT) {
        _Log("ReadEntity[%u]: index >= max (%u)", (unsigned)index, (unsigned)SOBJ_MAX_COUNT);
        return FALSE;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ReadEntity[%u]: no CR3", (unsigned)index);
        return FALSE;
    }

    UINT64 entry_va = s_state.tiger_list_base + (UINT64)index * SOBJ_STRIDE;
    _Log("ReadEntity[%u]: reading from 0x%I64X (%u bytes)",
        (unsigned)index, entry_va, (unsigned)sizeof(SObjectRaw));

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va, out, sizeof(SObjectRaw));
    BYOVD_UNLOCK();

    if (ok) {
        _Log("ReadEntity[%u]: SUCCESS type=0x%04X alive=%d comp_hdl=0x%08X enc_pos=[0x%08X 0x%08X 0x%08X]",
            (unsigned)index,
            (unsigned)out->type,
            (unsigned)out->alive,
            (unsigned)out->comp_handle,
            *(uint32_t*)&out->enc_pos[0],
            *(uint32_t*)&out->enc_pos[1],
            *(uint32_t*)&out->enc_pos[2]);
    } else {
        _Log("ReadEntity[%u]: FAILED read at 0x%I64X", (unsigned)index, entry_va);
    }

    return ok;
}

/* ── SObjectList_ReadType ─────────────────────────────────────────────────── */
uint8_t SObjectList_ReadType(UINT32 index)
{
    if (!s_state.initialized || index >= SOBJ_MAX_COUNT) {
        _Log("ReadType[%u]: returning OBJ_TYPE_INVALID (init=%d)", (unsigned)index, (int)s_state.initialized);
        return (uint8_t)OBJ_TYPE_INVALID;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ReadType[%u]: no CR3, returning OBJ_TYPE_INVALID", (unsigned)index);
        return (uint8_t)OBJ_TYPE_INVALID;
    }

    UINT64 entry_va = s_state.tiger_list_base + (UINT64)index * SOBJ_STRIDE;
    uint8_t type = 0;

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va + SOBJ_OFF_TYPE, &type, 1);
    BYOVD_UNLOCK();

    _Log("ReadType[%u]: 0x%02X (ok=%d)", (unsigned)index, (unsigned)type, (int)ok);
    return ok ? type : (uint8_t)OBJ_TYPE_INVALID;
}

/* ── SObjectList_ReadAlive ────────────────────────────────────────────────── */
BOOL SObjectList_ReadAlive(UINT32 index)
{
    if (!s_state.initialized || index >= SOBJ_MAX_COUNT) {
        _Log("ReadAlive[%u]: returning FALSE (init=%d)", (unsigned)index, (int)s_state.initialized);
        return FALSE;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ReadAlive[%u]: no CR3, returning FALSE", (unsigned)index);
        return FALSE;
    }

    UINT64 entry_va = s_state.tiger_list_base + (UINT64)index * SOBJ_STRIDE;
    uint8_t alive = 0;

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va + SOBJ_OFF_ALIVE, &alive, 1);
    BYOVD_UNLOCK();

    _Log("ReadAlive[%u]: alive=%d (ok=%d)", (unsigned)index, (int)alive, (int)ok);
    return ok ? (alive != 0) : FALSE;
}

/* ── SObjectList_ReadCompHandle ───────────────────────────────────────────── */
uint32_t SObjectList_ReadCompHandle(UINT32 index)
{
    if (!s_state.initialized || index >= SOBJ_MAX_COUNT) {
        _Log("ReadCompHandle[%u]: returning 0 (init=%d)", (unsigned)index, (int)s_state.initialized);
        return 0;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ReadCompHandle[%u]: no CR3, returning 0", (unsigned)index);
        return 0;
    }

    UINT64 entry_va = s_state.tiger_list_base + (UINT64)index * SOBJ_STRIDE;
    uint32_t handle = 0;

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va + SOBJ_OFF_COMP_HANDLE, &handle, 4);
    BYOVD_UNLOCK();

    _Log("ReadCompHandle[%u]: 0x%08X (valid=%d ok=%d)",
        (unsigned)index, (unsigned)handle,
        (int)SObject_IsValidHandle(handle), (int)ok);
    return ok ? handle : 0;
}

/* ── SObjectList_ReadEncPos ───────────────────────────────────────────────── */
BOOL SObjectList_ReadEncPos(UINT32 index, float out_xyz[3])
{
    if (!out_xyz) {
        _Log("ReadEncPos[%u]: NULL output", (unsigned)index);
        return FALSE;
    }

    if (!s_state.initialized || index >= SOBJ_MAX_COUNT) {
        _Log("ReadEncPos[%u]: returning FALSE (init=%d)", (unsigned)index, (int)s_state.initialized);
        return FALSE;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) {
        _Log("ReadEncPos[%u]: no CR3", (unsigned)index);
        return FALSE;
    }

    UINT64 entry_va = s_state.tiger_list_base + (UINT64)index * SOBJ_STRIDE;

    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va + SOBJ_OFF_ENC_POS_A, out_xyz, 12);
    BYOVD_UNLOCK();

    if (ok) {
        uint32_t raw[3];
        memcpy(&raw[0], &out_xyz[0], 4);
        memcpy(&raw[1], &out_xyz[1], 4);
        memcpy(&raw[2], &out_xyz[2], 4);
        _Log("ReadEncPos[%u]: SUCCESS raw=[0x%08X 0x%08X 0x%08X]",
            (unsigned)index, raw[0], raw[1], raw[2]);
    } else {
        _Log("ReadEncPos[%u]: FAILED", (unsigned)index);
    }

    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HANDLE RESOLUTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_ResolveHandle ────────────────────────────────────────────── */
UINT64 SObjectList_ResolveHandle(UINT64 cr3, uint32_t h)
{
    if (h == 0 || h == 0xFFFFFFFFu) {
        _Log("ResolveHandle: handle 0x%08X is sentinel (0 or 0xFFFFFFFF)", (unsigned)h);
        return 0;
    }

    if (!s_state.datum_valid) {
        _Log("ResolveHandle: datum_table NOT valid (h=0x%08X)", (unsigned)h);
        return 0;
    }

    if ((h & 0x00FF0000u) != SOBJ_HANDLE_TAG) {
        _Log("ResolveHandle: handle 0x%08X FAILED tag check (expected 0x%08X)",
            (unsigned)h, (unsigned)SOBJ_HANDLE_TAG);
        return 0;
    }

    UINT32 salt = h >> 13;
    UINT32 idx = (((h >> 13) | 0xFFC0000u) >> 18u) & (h >> 13);

    if (idx > SOBJ_DATUM_MAX_IDX) {
        _Log("ResolveHandle: idx %I64u > max (0x%X), h=0x%08X salt=0x%08X",
            (UINT64)idx, (unsigned)SOBJ_DATUM_MAX_IDX, (unsigned)h, (unsigned)salt);
        return 0;
    }

    UINT64 v10 = s_state.datum_table_va + idx * 64ULL;

    DatumRowData row = {0};
    UINT64 mask = 0;

    BYOVD_LOCK();
    BOOL ok_row = BYOVD_ReadVA(cr3, v10 + 8, &row, sizeof(row));
    if (ok_row && row.entry_base) {
        UINT64 v11 = row.entry_base + (UINT64)row.stride * (UINT64)(h & SOBJ_HANDLE_ENTRY_MASK);
        BYOVD_ReadVA(cr3, v11 + 8, &mask, 8);
    }
    BYOVD_UNLOCK();

    if (!ok_row) {
        _Log("ResolveHandle: datum table read failed at v10=0x%I64X (idx=%I64u)",
            v10, idx);
        return 0;
    }

    if (!row.entry_base) {
        _Log("ResolveHandle: entry_base=0, v10=0x%I64X idx=%I64u", v10, idx);
        return 0;
    }

    UINT64 v11 = row.entry_base + (UINT64)row.stride * (UINT64)(h & SOBJ_HANDLE_ENTRY_MASK);
    UINT64 ptr = v11 - (mask & (UINT64)(INT64)row.adj);

    if (ptr <= 0x1000000ULL || ptr >= 0x800000000000ULL) {
        _Log("ResolveHandle: ptr 0x%I64X out of range (h=0x%08X v11=0x%I64X mask=0x%I64X adj=%d)",
            ptr, (unsigned)h, v11, mask, (int)row.adj);
        return 0;
    }

    _Log("ResolveHandle: SUCCESS h=0x%08X -> idx=%I64u entry_base=0x%I64X stride=%u adj=%d v11=0x%I64X mask=0x%I64X ptr=0x%I64X",
        (unsigned)h, idx, row.entry_base, (unsigned)row.stride, (int)row.adj, v11, mask, ptr);

    return ptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * COMPONENT CHAIN WALK
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_WalkComponents ───────────────────────────────────────────── */
int SObjectList_WalkComponents(UINT64 cr3, uint32_t comp_handle,
                               SObjectCompCallback callback, void *ctx)
{
    _Log("WalkComponents: starting with comp_handle=0x%08X", (unsigned)comp_handle);

    if (!callback) {
        _Log("WalkComponents: NULL callback");
        return 0;
    }

    if (comp_handle == 0 || comp_handle == 0xFFFFFFFFu) {
        _Log("WalkComponents: invalid handle");
        return 0;
    }

    uint32_t h = comp_handle;
    int count = 0;

    for (int i = 0; i < SOBJ_CHAIN_WALK_MAX; i++) {
        if (h == 0 || h == 0xFFFFFFFFu) {
            _Log("WalkComponents: stop at iteration %d (h=0x%08X)", i, (unsigned)h);
            break;
        }

        _Log("WalkComponents: iteration %d resolving h=0x%08X", i, (unsigned)h);

        UINT64 node = SObjectList_ResolveHandle(cr3, h);
        if (!node) {
            _Log("WalkComponents: resolve failed at iteration %d h=0x%08X", i, (unsigned)h);
            break;
        }

        /* Read the node header for diagnostics */
        uint16_t flags = 0, type_ref = 0;
        uint32_t match_id = 0, schema_h = 0, data_h = 0, next_h = 0;
        uint8_t state = 0;

        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_FLAGS,     &flags,    2);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_TYPE_REF,   &type_ref, 2);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_MATCH_ID,   &match_id, 4);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_SCHEMA_H,   &schema_h, 4);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_DATA_H,     &data_h,   4);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_STATE,      &state,    1);
        BYOVD_ReadVA(cr3, node + SOBJ_COMP_OFF_NEXT_H,     &next_h,   4);
        BYOVD_UNLOCK();

        _Log("WalkComponents: node[%d] @0x%I64X flags=0x%04X type_ref=0x%04X match_id=0x%08X schema_h=0x%08X data_h=0x%08X state=%d next_h=0x%08X",
            i, node,
            (unsigned)flags, (unsigned)type_ref,
            (unsigned)match_id, (unsigned)schema_h,
            (unsigned)data_h, (unsigned)state,
            (unsigned)next_h);

        callback(node, ctx);
        count++;

        h = next_h;
    }

    _Log("WalkComponents: visited %d component(s)", count);
    return count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BONE READING
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_ReadBoneCount ────────────────────────────────────────────── */
int SObjectList_ReadBoneCount(UINT64 cr3, UINT64 comp_ptr)
{
    if (!cr3 || !comp_ptr) {
        _Log("ReadBoneCount: invalid params (cr3=0x%I64X comp_ptr=0x%I64X)", cr3, comp_ptr);
        return -1;
    }

    int32_t count = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, comp_ptr + SOBJ_BONE_COUNT_OFF, &count, 4);
    BYOVD_UNLOCK();

    if (!ok) {
        _Log("ReadBoneCount: read FAILED at comp+0x%X (comp=0x%I64X)",
            (unsigned)SOBJ_BONE_COUNT_OFF, comp_ptr);
        return -1;
    }

    if (count < 0 || count > 256) {
        _Log("ReadBoneCount: count=%d OUT OF RANGE (comp=0x%I64X)", (int)count, comp_ptr);
        return -1;
    }

    _Log("ReadBoneCount: %d bones at comp=0x%I64X", (int)count, comp_ptr);
    return (int)count;
}

/* ── SObjectList_ReadBones ────────────────────────────────────────────────── */
int SObjectList_ReadBones(UINT64 cr3, UINT64 comp_ptr,
                          float *out_bones, int max_bones)
{
    if (!cr3 || !comp_ptr || !out_bones || max_bones <= 0) {
        _Log("ReadBones: invalid params (comp_ptr=0x%I64X out=%p max=%d)",
            comp_ptr, (void*)out_bones, max_bones);
        return 0;
    }

    int bone_count = SObjectList_ReadBoneCount(cr3, comp_ptr);
    if (bone_count <= 0) {
        _Log("ReadBones: no bones (count=%d)", bone_count);
        return 0;
    }

    int to_read = (bone_count < max_bones) ? bone_count : max_bones;
    _Log("ReadBones: reading %d/%d bones from comp=0x%I64X", to_read, bone_count, comp_ptr);

    int success_count = 0;
    for (int i = 0; i < to_read; i++) {
        UINT64 bone_addr = comp_ptr + SOBJ_BONE_ARRAY_OFF + (UINT64)i * SOBJ_BONE_STRIDE;
        float xyz[3];

        BYOVD_LOCK();
        BOOL ok = BYOVD_ReadVA(cr3, bone_addr + SOBJ_BONE_POS_X, xyz, 12);
        BYOVD_UNLOCK();

        if (!ok) {
            _Log("ReadBones: FAILED at bone[%d] addr=0x%I64X", i, bone_addr);
            break;
        }

        out_bones[i * 3 + 0] = xyz[0];
        out_bones[i * 3 + 1] = xyz[1];
        out_bones[i * 3 + 2] = xyz[2];
        success_count++;

        _Log("ReadBones: bone[%d] @ 0x%I64X = (%f, %f, %f)", i, bone_addr, xyz[0], xyz[1], xyz[2]);
    }

    _Log("ReadBones: done, %d/%d bones read successfully", success_count, to_read);
    return success_count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * UTILITY
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── SObjectList_IsPositionValid ──────────────────────────────────────────── */
BOOL SObjectList_IsPositionValid(const float pos[3])
{
    if (!pos) {
        _Log("IsPositionValid: NULL pointer -> FALSE");
        return FALSE;
    }

    /* Reject NaN/Inf */
    for (int i = 0; i < 3; i++) {
        UINT32 bits;
        memcpy(&bits, &pos[i], 4);
        if ((bits & 0x7F800000u) == 0x7F800000u) {
            _Log("IsPositionValid: pos[%d]=%f is NaN/Inf -> FALSE", i, pos[i]);
            return FALSE;
        }
    }

    /* Reject zero-ish positions */
    float mag = (float)(fabs(pos[0]) + fabs(pos[1]) + fabs(pos[2]));
    if (mag < 0.01f) {
        _Log("IsPositionValid: mag=%f too small -> FALSE", mag);
        return FALSE;
    }

    /* Reject extreme values */
    if (fabs(pos[0]) > 500000.0f ||
        fabs(pos[1]) > 500000.0f ||
        fabs(pos[2]) > 500000.0f) {
        _Log("IsPositionValid: pos=(%f,%f,%f) out of bounds -> FALSE",
            pos[0], pos[1], pos[2]);
        return FALSE;
    }

    _Log("IsPositionValid: pos=(%f,%f,%f) -> TRUE", pos[0], pos[1], pos[2]);
    return TRUE;
}

#else /* DMA or External build */

#include "sobject_list.h"

SObjectListState g_sobjState = { 0 };

BOOL SObjectList_Init(void) { return FALSE; }
void SObjectList_Reset(void) { }
BOOL SObjectList_IsReady(void) { return FALSE; }
UINT64 SObjectList_GetArrayBase(void) { return 0; }
UINT64 SObjectList_GetStride(void) { return 0; }
UINT32 SObjectList_GetMaxCount(void) { return 0; }

BOOL SObjectList_ReadEntity(UINT32 index, SObjectRaw *out) { return FALSE; }
uint8_t SObjectList_ReadType(UINT32 index) { return 0; }
BOOL SObjectList_ReadAlive(UINT32 index) { return FALSE; }
uint32_t SObjectList_ReadCompHandle(UINT32 index) { return 0; }
BOOL SObjectList_ReadEncPos(UINT32 index, float out_xyz[3]) { return FALSE; }

UINT64 SObjectList_ResolveHandle(UINT64 cr3, uint32_t h) { return 0; }

int SObjectList_WalkComponents(UINT64 cr3, uint32_t comp_handle, SObjectCompCallback callback, void *ctx) { return 0; }

int SObjectList_ReadBoneCount(UINT64 cr3, UINT64 comp_ptr) { return 0; }
int SObjectList_ReadBones(UINT64 cr3, UINT64 comp_ptr, float *out_bones, int max_bones) { return 0; }
BOOL SObjectList_IsPositionValid(const float pos[3]) { return FALSE; }

#endif /* !SERAPH_DMA_BUILD && !SERAPH_EXTERNAL_BUILD */