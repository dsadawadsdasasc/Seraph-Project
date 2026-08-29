#ifndef KILL_AURA_H
#define KILL_AURA_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Kill Aura — port of the CE "killaura" script.
 *
 *   AOB (anchor, 6 bytes — drops the CE `0?` low-nibble wildcard prefix):
 *     F3 0F 10 41 20 32      movss xmm0,[rcx+0x20] ; xor al,al
 *
 *   Stolen at hookVA = matchVA + 0  (5 bytes):
 *     F3 0F 10 41 20         movss xmm0,[rcx+0x20]
 *
 * Behavior (matches CE):
 *   while enabled, every call writes the slider-controlled float into
 *   [rcx+0x20] *before* loading xmm0, so xmm0 returns with the boosted
 *   value (default 1000.0).
 *
 * On disable:
 *   1. Slider value is set to 0 in the cave (any in-flight execution
 *      between step 1 and 4 stores 0).
 *   2. The most recent rcx (captured by the shellcode into a mailbox)
 *      gets a one-shot BYOVD write of 0.0f to [rcx+0x20], so the last
 *      target reverts immediately instead of carrying the boosted value.
 *   3. LazyHook is removed; original 5-byte movss is restored. */

#ifdef SERAPH_EXCLUDE_KILLAURA

#define KILLAURA_AOB_LEN 13

static inline void KillAura_SetPreScanResult(UINT64 va) { (void)va; }
static inline void KillAura_OnAttach(void) {}
static inline void KillAura_OnDetach(void) {}
static inline void KillAura_SetEnabled(BOOL state) { (void)state; }
static inline void KillAura_SetMultiplier(int value) { (void)value; }
static inline int  KillAura_GetMultiplier(void) { return 100; }
static inline BOOL KillAura_IsReady(void) { return FALSE; }

#else

extern const UINT8 k_killaura_pat[];
extern const UINT8 k_killaura_mask[];
#define KILLAURA_AOB_LEN 13

void KillAura_SetPreScanResult(UINT64 va);
void KillAura_OnAttach(void);
void KillAura_OnDetach(void);

void KillAura_SetEnabled(BOOL state);
void KillAura_SetMultiplier(int value);
int  KillAura_GetMultiplier(void);
BOOL KillAura_IsReady(void);

#endif

#ifdef __cplusplus
}
#endif

#endif /* KILL_AURA_H */
