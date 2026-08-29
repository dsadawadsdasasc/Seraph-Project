#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── TP entry limits ─────────────────────────────────────────────────────── */
#define TP_MAX_SLOTS       32
#define TP_NAME_MAX        48

/* ── TP Entry ───────────────────────────────────────────────────────────────
 * A saved teleport destination: position (rigidbody coords) + viewangles. */
typedef struct {
    float  x, y, z;          /* world coords (RB_OFF_COORDS = 0x1C0) */
    float  viewYaw;          /* camera yaw   */
    float  viewPitch;        /* camera pitch */
    WCHAR  name[TP_NAME_MAX];
    BOOL   valid;            /* FALSE = empty slot */
    int    hotkey;           /* 0 = no hotkey, otherwise VK code */
} TPSlot;

/* ── Public API ──────────────────────────────────────────────────────────── */

/* Must be called once after attach to zero state. */
void TP_Init(void);

/* Save the local player's current position + camera into the next free slot.
 * Returns the slot index on success, -1 if no free slot or player not resolved. */
int  TP_SaveCurrent(const WCHAR* name);

/* Teleport to the given slot index (0-based).  Sets position, zeros velocity,
 * and optionally restores the saved viewangles.  Does nothing if slot is empty
 * or the player entity is not resolved. */
void TP_TeleportTo(int idx);

/* Delete (invalidate) a slot. */
void TP_Delete(int idx);

/* Set/get the hotkey for a slot (0 = none). */
void TP_SetHotkey(int idx, int vk);
int  TP_GetHotkey(int idx);

/* ── Accessors (for GUI rendering) ───────────────────────────────────────── */
int  TP_GetCount(void);
const TPSlot* TP_GetSlot(int idx);

void TP_TeleportNext(void);
void TP_TeleportPrev(void);

/* ── TP config save/load (JSON in Documents/Seraph/TP_Configs/) ─────────── */
void TP_SaveConfig(const char* name);
void TP_LoadConfig(const char* name);
void TP_DeleteConfigFile(const char* name);

#ifdef __cplusplus
}
#endif
