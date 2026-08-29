#include "teleports.h"
#include "esp.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <stdio.h>
#include <wchar.h>
#include "havok.h"
#include "byovd.h"
#include "fly.h"
#include "attach.h"
#include "tigerlist.h"
#include <string.h>
#include <shlobj.h>

/* ── Internal state ──────────────────────────────────────────────────────── */
static TPSlot g_slots[TP_MAX_SLOTS];
static int    g_count = 0;
static BOOL   g_initialized = FALSE;
static int    g_lastTpIdx = -1;

/* ── Public API ──────────────────────────────────────────────────────────── */

void TP_Init(void)
{
    if (g_initialized) return;
    memset(g_slots, 0, sizeof(g_slots));
    g_count = 0;
    g_initialized = TRUE;
    g_lastTpIdx = -1;
}

int TP_SaveCurrent(const WCHAR* name)
{
    if (!g_initialized) TP_Init();

    /* Find first free slot */
    int idx = -1;
    for (int i = 0; i < TP_MAX_SLOTS; i++)
    {
        if (!g_slots[i].valid)
        {
            idx = i;
            break;
        }
    }
    if (idx < 0) return -1;

    UINT64 cr3 = GetDestiny2CR3();
    float px = 0.0f, py = 0.0f, pz = 0.0f;

    /* 1. If Fly/FlyDir is enabled, try reading from fly active local player rigid body or HavokState first */
    if (Fly_IsEnabled() || FlyDir_IsEnabled())
    {
        UINT64 flyEp = Fly_GetLpEp();
        if (cr3 && flyEp && flyEp >= 0x10000ULL)
        {
            float lpPos[3] = {0.0f};
            BYOVD_LOCK();
            BOOL ok = BYOVD_ReadVA(cr3, flyEp + RB_OFF_COORDS, lpPos, 12);
            BYOVD_UNLOCK();
            if (ok && (lpPos[0] != 0.0f || lpPos[1] != 0.0f || lpPos[2] != 0.0f))
            {
                px = lpPos[0];
                py = lpPos[1];
                pz = lpPos[2];
            }
        }

        if (px == 0.0f && py == 0.0f && pz == 0.0f)
        {
            px = g_HavokState.local_pos.x;
            py = g_HavokState.local_pos.y;
            pz = g_HavokState.local_pos.z;
        }
    }

    /* 2. Try reading from TigerList if not resolved above (e.g. Fly is disabled, or Fly coordinate reading failed) */
    if (px == 0.0f && py == 0.0f && pz == 0.0f)
    {
        float tlPos[3] = {0.0f};
        if (TigerList_ReadLPPosition(tlPos) && (tlPos[0] != 0.0f || tlPos[1] != 0.0f || tlPos[2] != 0.0f))
        {
            px = tlPos[0];
            py = tlPos[1];
            pz = tlPos[2];
        }
    }

    /* 3. Try reading from fly active local player rigid body if not resolved above (Fly was disabled but we can still check) */
    if (cr3 && px == 0.0f && py == 0.0f && pz == 0.0f)
    {
        UINT64 flyEp = Fly_GetLpEp();
        if (flyEp && flyEp >= 0x10000ULL)
        {
            float lpPos[3] = {0.0f};
            BYOVD_LOCK();
            BOOL ok = BYOVD_ReadVA(cr3, flyEp + RB_OFF_COORDS, lpPos, 12);
            BYOVD_UNLOCK();
            if (ok && (lpPos[0] != 0.0f || lpPos[1] != 0.0f || lpPos[2] != 0.0f))
            {
                px = lpPos[0];
                py = lpPos[1];
                pz = lpPos[2];
            }
        }
    }

    /* 4. Fallback to HavokState (populated by Havok_GetEntities) */
    if (px == 0.0f && py == 0.0f && pz == 0.0f)
    {
        px = g_HavokState.local_pos.x;
        py = g_HavokState.local_pos.y;
        pz = g_HavokState.local_pos.z;
    }

    /* 4. Fallback mock coordinates if game is not attached or position is zero */
    if (px == 0.0f && py == 0.0f && pz == 0.0f)
    {
        px = 100.0f;
        py = 200.0f;
        pz = 300.0f;
    }

    /* Fill slot */
    g_slots[idx].x = px;
    g_slots[idx].y = py;
    g_slots[idx].z = pz;
    g_slots[idx].viewYaw = 0.0f;
    g_slots[idx].viewPitch = 0.0f;
    g_slots[idx].valid = TRUE;
    g_slots[idx].hotkey = 0;

    if (name && name[0])
        wcsncpy_s(g_slots[idx].name, TP_NAME_MAX, name, _TRUNCATE);
    else
        wcscpy_s(g_slots[idx].name, TP_NAME_MAX, L"TP");

    if (idx + 1 > g_count)
        g_count = idx + 1;

    return idx;
}

static UINT64 find_rigid_body(UINT64 cr3, UINT64 hkp_world_va, float x, float y, float z, float maxDist2, UINT64 motion_vtable, int unused)
{
    (void)cr3;
    (void)hkp_world_va;
    (void)unused;
    HavokEntity hents[HAVOK_MAX_RESULTS];
    int n = Havok_GetEntities(hents, HAVOK_MAX_RESULTS);
    UINT64 bestEp = 0;
    float bestDist2 = maxDist2;

    for (int i = 0; i < n; i++) {
        if (motion_vtable && hents[i].motion_vtable != motion_vtable) continue;
        
        float dx = hents[i].coords.x - x;
        float dy = hents[i].coords.y - y;
        float dz = hents[i].coords.z - z;
        float d2 = dx * dx + dy * dy + dz * dz;
        
        if (d2 < bestDist2) {
            bestDist2 = d2;
            bestEp = hents[i].entity_ptr;
        }
    }
    return bestEp;
}

void TP_TeleportTo(int idx)
{
    if (!g_initialized) TP_Init();
    if (idx < 0 || idx >= TP_MAX_SLOTS) return;
    if (!g_slots[idx].valid) return;

    /* Only run TP if Destiny 2 or the cheat menu is the active foreground window */
    HWND hActive = GetForegroundWindow();
    if (hActive) {
        DWORD activePid = 0;
        GetWindowThreadProcessId(hActive, &activePid);

        WCHAR szTitle[128] = {0};
        GetWindowTextW(hActive, szTitle, 128);

        BOOL isGameActive = (wcscmp(szTitle, L"Destiny 2") == 0);
        BOOL isMenuActive = (activePid == GetCurrentProcessId());

        if (!isGameActive && !isMenuActive) {
            return; /* Ignore TP: user is alt-tabbed */
        }
    }

    g_lastTpIdx = idx;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 lpAddr = Fly_GetLpEp();
    if (!lpAddr) {
        /* If fly is not active, resolve the player's rigid body on the fly */
        if (!g_HavokState.hkp_world_va) {
            /* Try to initialize Havok if not done */
            Havok_Init();
        }
        if (g_HavokState.hkp_world_va) {
            float tlPos[3] = {0.0f};
            if (TigerList_ReadLPPosition(tlPos)) {
                lpAddr = find_rigid_body(cr3, g_HavokState.hkp_world_va, tlPos[0], tlPos[1], tlPos[2], 225.0f, g_HavokState.hkp_motion_vtable, 0);
            }
        }
    }

    if (!lpAddr) return;

    /* Write position with a tiny delta first to force immediate physics refresh, then final coords */
    float temp_coords[3] = { g_slots[idx].x, g_slots[idx].y, g_slots[idx].z - 0.05f };
    float final_coords[3] = { g_slots[idx].x, g_slots[idx].y, g_slots[idx].z };
    float zero[3] = {0.0f, 0.0f, 0.0f};

    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, lpAddr + RB_OFF_COORDS, temp_coords, sizeof(temp_coords));
    BYOVD_WriteVA(cr3, lpAddr + RB_OFF_COORDS, final_coords, sizeof(final_coords));
    /* Zero velocity to prevent sliding */
    BYOVD_WriteVA(cr3, lpAddr + RB_OFF_VELOCITY, zero, sizeof(zero));
    BYOVD_UNLOCK();
}

void TP_Delete(int idx)
{
    if (!g_initialized) TP_Init();
    if (idx < 0 || idx >= TP_MAX_SLOTS) return;
    if (!g_slots[idx].valid) return;

    memset(&g_slots[idx], 0, sizeof(TPSlot));
    g_slots[idx].valid = FALSE;

    if (g_lastTpIdx == idx) {
        g_lastTpIdx = -1;
    }

    /* Recalculate count */
    int maxIdx = -1;
    for (int i = 0; i < TP_MAX_SLOTS; i++)
    {
        if (g_slots[i].valid && i > maxIdx)
            maxIdx = i;
    }
    g_count = maxIdx + 1;
}

void TP_SetHotkey(int idx, int vk)
{
    if (!g_initialized) TP_Init();
    if (idx < 0 || idx >= TP_MAX_SLOTS) return;
    g_slots[idx].hotkey = vk;
}

int TP_GetHotkey(int idx)
{
    if (!g_initialized) TP_Init();
    if (idx < 0 || idx >= TP_MAX_SLOTS) return 0;
    return g_slots[idx].hotkey;
}

int TP_GetCount(void)
{
    if (!g_initialized) TP_Init();
    return g_count;
}

const TPSlot* TP_GetSlot(int idx)
{
    if (!g_initialized) TP_Init();
    if (idx < 0 || idx >= TP_MAX_SLOTS) return NULL;
    if (!g_slots[idx].valid) return NULL;
    return &g_slots[idx];
}

/* ── TP config save/load ─────────────────────────────────────────────────── */

static void TP_GetConfigDir(WCHAR* out, int outChars) {
    out[0] = 0;
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, out))) {
        /* XOR-decode L"\\Seraph" (key 0xA5) — avoids project name in .rdata */
        static const USHORT _sep[] = {0xF9, 0xF6, 0xC0, 0xD7, 0xC4, 0xD5, 0xCD};
        WCHAR _sd[8]; for(int _i=0;_i<7;_i++) _sd[_i]=(WCHAR)(_sep[_i]^0xA5u); _sd[7]=0;

        /* XOR-decode L"\\Seraph\\TP_Configs" (key 0xA5) */
        static const USHORT _stpc[] = {0xF9, 0xF6, 0xC0, 0xD7, 0xC4, 0xD5, 0xCD, 0xF9, 0xF1, 0xF5, 0xFA, 0xE6, 0xCA, 0xCB, 0xC3, 0xCC, 0xC2, 0xD6};
        WCHAR _stpcW[19]; for(int _i=0;_i<18;_i++) _stpcW[_i]=(WCHAR)(_stpc[_i]^0xA5u); _stpcW[18]=0;

        // First create parent folder
        WCHAR parent[MAX_PATH];
        wcscpy_s(parent, MAX_PATH, out);
        wcscat_s(parent, MAX_PATH, _sd);
        CreateDirectoryW(parent, NULL);

        // Then create the TP_Configs subfolder
        wcscat_s(out, outChars, _stpcW);
        CreateDirectoryW(out, NULL);
    }
}

void TP_SaveConfig(const char* name)
{
    if (!g_initialized) TP_Init();
    WCHAR dir[MAX_PATH];
    TP_GetConfigDir(dir, MAX_PATH);
    if (!dir[0]) return;

    WCHAR path[MAX_PATH];
    swprintf_s(path, MAX_PATH, L"%s\\%hs.tp", dir, name);

    HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF == INVALID_HANDLE_VALUE) return;

    DWORD written = 0;
    WriteFile(hF, &g_count, sizeof(g_count), &written, NULL);
    for (int i = 0; i < TP_MAX_SLOTS; i++) {
        if (g_slots[i].valid)
            WriteFile(hF, &g_slots[i], sizeof(TPSlot), &written, NULL);
    }
    CloseHandle(hF);
}

void TP_LoadConfig(const char* name)
{
    if (!g_initialized) TP_Init();
    WCHAR dir[MAX_PATH];
    TP_GetConfigDir(dir, MAX_PATH);
    if (!dir[0]) return;

    WCHAR path[MAX_PATH];
    swprintf_s(path, MAX_PATH, L"%s\\%hs.tp", dir, name);

    HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hF == INVALID_HANDLE_VALUE) return;

    /* Clear existing slots */
    memset(g_slots, 0, sizeof(g_slots));
    g_count = 0;
    g_lastTpIdx = -1;

    DWORD read = 0;
    int count = 0;
    if (!ReadFile(hF, &count, sizeof(count), &read, NULL) || read != sizeof(count)) {
        CloseHandle(hF);
        return;
    }
    if (count < 0 || count > TP_MAX_SLOTS) count = 0;

    for (int i = 0; i < count; i++) {
        TPSlot slot = {0};
        if (ReadFile(hF, &slot, sizeof(TPSlot), &read, NULL) && read == sizeof(TPSlot)) {
            g_slots[i] = slot;
        }
    }
    g_count = count;
    CloseHandle(hF);
}

void TP_DeleteConfigFile(const char* name)
{
    WCHAR dir[MAX_PATH];
    TP_GetConfigDir(dir, MAX_PATH);
    if (!dir[0]) return;

    WCHAR path[MAX_PATH];
    swprintf_s(path, MAX_PATH, L"%s\\%hs.tp", dir, name);
    DeleteFileW(path);
}

void TP_TeleportNext(void)
{
    if (!g_initialized) TP_Init();
    int start = (g_lastTpIdx == -1) ? 0 : (g_lastTpIdx + 1);
    for (int i = 0; i < TP_MAX_SLOTS; i++)
    {
        int idx = (start + i) % TP_MAX_SLOTS;
        if (g_slots[idx].valid)
        {
            TP_TeleportTo(idx);
            break;
        }
    }
}

void TP_TeleportPrev(void)
{
    if (!g_initialized) TP_Init();
    int start = (g_lastTpIdx == -1) ? (TP_MAX_SLOTS - 1) : (g_lastTpIdx - 1);
    for (int i = 0; i < TP_MAX_SLOTS; i++)
    {
        int idx = start - i;
        while (idx < 0) idx += TP_MAX_SLOTS;
        idx = idx % TP_MAX_SLOTS;
        if (g_slots[idx].valid)
        {
            TP_TeleportTo(idx);
            break;
        }
    }
}
