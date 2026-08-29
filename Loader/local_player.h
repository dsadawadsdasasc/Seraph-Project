#pragma once
#include <windows.h>

/* local_player.h — LocalPlayer resolver.
 *
 * Resolves the local player index within the TigerList and determines
 * the local player entity VA based on active slot markers and identity keys.
 */

extern UINT64 g_local_identity_rva;
extern UINT64 g_character_motion_vtable_rva;

#define LOCAL_IDENTITY              g_local_identity_rva
#define CHARACTER_MOTION_VTABLE     g_character_motion_vtable_rva

#ifdef __cplusplus
extern "C" {
#endif

void   LP_OnAttach(void);      /* initializes local player tracking state */
void   LP_OnDetach(void);      /* resets cached state */
void   LP_Tick(void);          /* performs periodic index and state validation */
int    LP_GetLocalPlayerIndex(void); /* returns cached local player index (-1 = not resolved) */
void   LP_ResolveGlobalsIfNeeded(UINT64 cr3, UINT64 d2Base);
void   LP_ResetSoftState(void);
UINT64 LP_GetEntityVA(void);
UINT64 LP_GetLocalPlayerRigidBody(void);
UINT32 LP_GetLocalPlayerSObjectHandle(void);
BOOL   LP_GetLocalPlayerSObjectPos(float outPos[3]);
UINT64 LP_GetLocalPlayerSObjectVA(void);

#ifdef __cplusplus
}
#endif

