#include "suicide.h"
#include "fly.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"

/* Havok RigidBody position offsets (ep-relative) */
#define SUICIDE_OFF_POS_X   0x1C0u   /* east   */
#define SUICIDE_OFF_POS_Z   0x1C4u   /* north  */
#define SUICIDE_OFF_POS_Y   0x1C8u   /* height */

static int s_hotkey = 0;  /* 0 = unbound */

void Suicide_SetHotkey(int vk) { s_hotkey = vk; }
int  Suicide_GetHotkey(void)   { return s_hotkey; }

void Suicide_Trigger(void)
{
    /* Removed Fly_SetResolveOnly */

    UINT64 ep = Fly_GetLpEp();
    if (!ep) return;   /* Not yet resolved — retry on next press. */

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    /* Teleport coordinates to 2000 — custom teleport location. */
    float pos[3] = {2000.0f, 2000.0f, 2000.0f};
    BYOVD_LOCK();
    BYOVD_WriteVA(cr3, ep + SUICIDE_OFF_POS_X, pos, sizeof(pos));
    BYOVD_UNLOCK();
}
