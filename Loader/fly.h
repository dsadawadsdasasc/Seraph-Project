#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AOB patterns exposed for FeatureInitThread mega multi-pattern scan. */
extern const UINT8 k_cam_pat[];
extern const UINT8 k_cam_mask[];

/* Pre-scan handoff: FeatureInitThread sets these from the mega multi-pattern
 * scan so Fly_OnAttach skips its own scans. */
void Fly_SetCamPreScanResult(UINT64 va);
void Fly_SetLpEpPreScanResult(UINT64 va);  /* LP hook AOB pre-scan handoff */

/* Resolves camera AOB. Call after AttachToDestiny2 succeeds. */
void Fly_OnAttach(void);

/* Resets state when game closes (removes camera hook). */
void Fly_OnDetach(void);

BOOL Fly_RestoreCamHookOnDemand(UINT64 cr3, UINT64 d2Base);

/* Resets per-session ep / SObject / TL state WITHOUT removing the installed
 * camera hook.  Safe to call from Attach_Invalidate on game-process exit so
 * stale pointers never bleed into the next game session.  Also callable during
 * live activity transitions for an immediate soft reset independent of the
 * WATCHDOG 3-second timer. */
void Fly_ResetSoftState(void);

/* Call from the render loop at ~120Hz while fly is active.
 * speed: 1-10 slider value (maps to 5-50 units/s). */
void Fly_Tick(int speedWASD, int speedDir);

void Fly_SetEnabled(BOOL en);
BOOL Fly_IsEnabled(void);

void FlyDir_SetEnabled(BOOL en);
BOOL FlyDir_IsEnabled(void);

/* Returns the current LP entity pointer.
 * Uses Havok scan (s_stableEp), fed by the k_lpep_pat LP hook mailbox
 * via HookSeeder. */
UINT64 Fly_GetLpEp(void);

/* Resolves the decrypted PObjects pointer (for ESP decryption). */
UINT64 Fly_GetPObjDecryptedVA(void);

void Fly_GetCamTrig(float* cY, float* sY, float* cP, float* sP);

/* Camera yaw/pitch at camBase+0x18/+0x1C (requires cam lazyhook from Fly_OnAttach). */
BOOL Fly_ReadCam(float* yaw, float* pitch, UINT64* camBaseOut);
BOOL Fly_WriteCam(float yaw, float pitch);

/* Returns the current camBase from the camera hook mailbox (0 if not available).
 * Same value that Fly_ReadCam returns in camBaseOut, without reading angles. */
UINT64 Fly_GetCamBase(void);

/* Returns the current camera/player world position from the fly hook mailbox.
 * Same Havok coordinate system as entity worldPos. Returns FALSE if not yet valid. */
BOOL Fly_GetCamWorldPos(float* x, float* y, float* z);

/* Returns the camera cave VA (used by ammo.c to prevent collisions) */
UINT64 Fly_GetCaveVA(void);

#ifdef __cplusplus
}
#endif
