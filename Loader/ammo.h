#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SERAPH_DMA_BUILD
/* Call after AttachToDestiny2 succeeds — scans for hook point and installs hook */
void Ammo_OnAttach(void);

/* Set enable state.  Activate while ammo is FULL to freeze at max. */
void Ammo_SetEnabled(BOOL en);
BOOL Ammo_IsEnabled(void);

/* Custom value override (1..99). If 0, uses standard infinite ammo (increment). */
void Ammo_SetValue(UINT32 val);
UINT32 Ammo_GetValue(void);

/* Call every render frame (tick does nothing if disabled or <50ms since last write) */
void Ammo_Tick(void);

/* Uninstall hook and release state (call on detach / exit) */
void Ammo_OnDetach(void);

/* Cave VA used by this module (0 if not found) */
UINT64 Ammo_GetCaveVA(void);

/* Resolved get_ammo_key absolute function VA */
UINT64 Ammo_GetGetKeyVA(void);
#else
static inline void Ammo_OnAttach(void) {}
static inline void Ammo_SetEnabled(BOOL en) { (void)en; }
static inline BOOL Ammo_IsEnabled(void) { return FALSE; }
static inline void Ammo_SetValue(UINT32 val) { (void)val; }
static inline UINT32 Ammo_GetValue(void) { return 0; }
static inline void Ammo_Tick(void) {}
static inline void Ammo_OnDetach(void) {}
static inline UINT64 Ammo_GetCaveVA(void) { return 0; }
static inline UINT64 Ammo_GetGetKeyVA(void) { return 0; }
#endif

#ifdef __cplusplus
}
#endif
