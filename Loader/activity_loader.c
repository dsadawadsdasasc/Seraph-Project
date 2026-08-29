
#include "ThemidaSDK.h"
#include "activity_loader.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include "cave_finder.h"
#include "lazyhook.h"
static int    s_hookId      = -1;
static UINT64 s_caveVA      = 0;
static int    s_activityId  = 0;

#include "xor_strings.h"

void ActivityLoader_OnAttach(void)
{
    s_hookId = -1;
    s_caveVA = 0;
    s_activityId = 0;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    /* Initialize hookVA using SecureReadStatic */
    UINT64 hookVA = d2Base + SecureReadStatic(&OBF_OFF_ActivityLoader);

    s_caveVA = CaveFinder_FindFirst(cr3, d2Base, 40);
    if (!s_caveVA) {
        DEBUG_FLY("[ActivityLoader] no cave found");
        return;
    }

    /* Make the page writable so our shellcode can store the pointer inside the cave */
    BYOVD_LOCK();
    BYOVD_SetPageWritable(cr3, s_caveVA);
    BYOVD_UNLOCK();

    /* Shellcode (24 bytes):
     * push rax
     * mov rax, rdi
     * add rax, rdx
     * mov [rip+2], rax
     * pop rax
     * nop
     * storage (8 bytes)
     */
    static const UINT8 sc[24] = {
        0x50,                               /* push rax */
        0x48, 0x89, 0xF8,                   /* mov rax, rdi */
        0x48, 0x01, 0xD0,                   /* add rax, rdx */
        0x48, 0x89, 0x05, 0x02, 0x00, 0x00, 0x00, /* mov [rip+2], rax */
        0x58,                               /* pop rax */
        0x90,                               /* nop */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* 8-byte mailbox */
    };

    s_hookId = LazyHook_Install(cr3, hookVA, 7, sc, sizeof(sc), s_caveVA);
    if (s_hookId >= 0) {
        DEBUG_FLY("[ActivityLoader] Hook installed OK id=%d at 0x%I64X", s_hookId, hookVA);
    } else {
        DEBUG_FLY("[ActivityLoader] Hook install FAILED");
        s_caveVA = 0;
    }
}

void ActivityLoader_OnDetach(void)
{
    UINT64 cr3 = GetDestiny2CR3();
    if (s_hookId >= 0 && cr3) {
        LazyHook_Remove(s_hookId, cr3);
    }
    s_hookId = -1;
    s_caveVA = 0;
}

BOOL ActivityLoader_IsHooked(void)
{
    return (s_hookId >= 0);
}

void ActivityLoader_SetActivityId(int id)
{
    s_activityId = id;
    if (s_hookId < 0 || !s_caveVA) {
        DEBUG_FLY("[ActivityLoader] SetActivityId ignored (not hooked)");
        return;
    }

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 capturedBase = 0;
    BYOVD_LOCK();
    /* The 8-byte storage is at s_caveVA + 16 */
    BYOVD_ReadVA(cr3, s_caveVA + 16, &capturedBase, 8);
    BYOVD_UNLOCK();

    if (capturedBase >= 0x10000ULL) {
        UINT16 val = (UINT16)id;
        BYOVD_LOCK();
        BYOVD_WriteVA(cr3, capturedBase + 0x0A, &val, 2);
        BYOVD_UNLOCK();
        DEBUG_FLY("[ActivityLoader] Applied activity ID %d to 0x%I64X", id, capturedBase + 0x0A);
    } else {
        DEBUG_FLY("[ActivityLoader] capturedBase is invalid (0x%I64X), wait for hook trigger", capturedBase);
    }
}

int ActivityLoader_GetActivityId(void)
{
    return s_activityId;
}
