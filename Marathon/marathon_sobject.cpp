/* marathon_sobject.cpp — Marathon SObject List reading and resolution */
#include "esp.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include <windows.h>
#include <stdio.h>

extern UINT64 g_RVA_SObjectList;

#include "debug.h"

static void _write_to_diag(const char* filename, const char* msg) {
    /* 1. Flush to main seraph_debug.log */
    WriteLogFileEx("seraph_debug.log", msg);

    /* 2. Flush to Downloads/filename.log */
    char path[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("USERPROFILE", path, MAX_PATH - 64);
    if (!n || n >= MAX_PATH - 64) return;
    lstrcatA(path, "\\Downloads\\");
    lstrcatA(path, filename);

    HANDLE hF = CreateFileA(path, FILE_APPEND_DATA,
        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(hF, msg, (DWORD)lstrlenA(msg), &w, NULL);
        CloseHandle(hF);
    }
}

static void _sobj_log(const char* format, ...) {
    char msg[512];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg) - 1, format, args);
    va_end(args);

    char buf[640];
    wsprintfA(buf, "[SOBJECT][%lu] %s\r\n", (unsigned long)GetTickCount(), msg);
    _write_to_diag("sobject.log", buf);
}

static void _sobj_hexdump(const char* label, UINT64 va, const void* data, size_t size) {
    if (!data || size == 0) return;
    _sobj_log("--- HEX DUMP: %s (VA: 0x%I64X, Size: %zu) ---", label, va, size);
    const BYTE* p = (const BYTE*)data;
    char line[128];
    for (size_t i = 0; i < size; i += 16) {
        int off = wsprintfA(line, "+0x%04X | ", (unsigned int)i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) off += wsprintfA(line + off, "%02X ", p[i + j]);
            else off += wsprintfA(line + off, "   ");
        }
        off += wsprintfA(line + off, "| ");
        for (size_t j = 0; j < 16 && (i + j) < size; j++) {
            BYTE c = p[i + j];
            line[off++] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        line[off++] = '\r';
        line[off++] = '\n';
        line[off] = '\0';
        _write_to_diag("sobject.log", line);
    }
    _sobj_log("--- END HEX DUMP ---");
}

extern "C" {

typedef struct {
    UINT32 index;
    BOOL   active;
    UINT32 bone_handle;
    UINT32 health_handle;
} MarathonSObjectRaw;

BOOL MarathonSObject_Read(UINT32 index, MarathonSObjectRaw *out) {
    if (!out || index >= 8192) return FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 base = GetDestiny2Base();
    if (!cr3 || !base || !g_RVA_SObjectList) return FALSE;

    UINT64 sobj_list_va = base + g_RVA_SObjectList;
    UINT64 entry_va = sobj_list_va + (UINT64)index * 0x150u;

    BYTE entry_buf[0x60]; /* reads up to 0x60 covering sentinel at 0x3C, bone_handle at 0x44 and health_handle at 0x4C */
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA(cr3, entry_va, entry_buf, sizeof(entry_buf));
    BYOVD_UNLOCK();

    if (!ok) {
        static DWORD lastFailLog = 0;
        if (GetTickCount() - lastFailLog > 5000) {
            _sobj_log("Read FAIL at index %u (VA: 0x%I64X)", index, entry_va);
            lastFailLog = GetTickCount();
        }
        return FALSE;
    }

    UINT32 sentinel = *(UINT32*)(entry_buf + 0x3C);
    
    static BOOL s_active_logged[8192] = { FALSE };
    
    if (sentinel == 0xFFFFFFFFu || sentinel == 0) {
        out->active = FALSE;
        if (s_active_logged[index]) {
            _sobj_log("SObject %u: Deactivated (sentinel=0x%08X at VA 0x%I64X)", index, sentinel, entry_va);
            s_active_logged[index] = FALSE;
        }
        return TRUE;
    }

    out->index = index;
    out->active = TRUE;
    out->bone_handle = *(UINT32*)(entry_buf + 0x44);
    out->health_handle = *(UINT32*)(entry_buf + 0x4C);

    if (!s_active_logged[index]) {
        _sobj_log("SObject %u: ACTIVATED at VA 0x%I64X! Sentinel=0x%08X, BoneHdl=0x%08X, HpHdl=0x%08X",
                  index, entry_va, sentinel, out->bone_handle, out->health_handle);
        char label[64];
        wsprintfA(label, "SObject[%u] Entry (0x60 bytes)", index);
        _sobj_hexdump(label, entry_va, entry_buf, sizeof(entry_buf));
        s_active_logged[index] = TRUE;
    }

    return TRUE;
}

}
