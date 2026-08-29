/* ── esp_overlay.h ────────────────────────────────────────────────────────── *
 * Dedicated layered, transparent, click-through full-screen window for the
 * ESP overlay. Independent from the main menu HWND so the ESP renders even
 * when the menu is hidden / when the game window is focused.
 *
 * Lifecycle:
 *   EspOverlay_Start()  — spawns render thread + window (idempotent)
 *   EspOverlay_Stop()   — signals the thread to exit, blocks briefly
 *
 * The render thread polls ESP_GetEntityBoxes() at ~60 Hz and draws a box
 * around every Havok entity (except the local player, which is degenerate
 * in FPS). Color-key magenta is used for transparency.                     */
#ifndef ESP_OVERLAY_H
#define ESP_OVERLAY_H

#ifdef __cplusplus
extern "C" {
#endif

void EspOverlay_Start(void);
void EspOverlay_Stop(void);
void EspOverlay_SetMaster(BOOL enable);
void EspOverlay_SetDrawBoxes(BOOL draw); /* TRUE = render ESP boxes; FALSE = aimbot-only */
void EspOverlay_SetDrawSkeleton(BOOL draw); /* DEV: TRUE = render TL-based skeleton dots */
void EspOverlay_SetHideAllies(BOOL hide);   /* TRUE = skip rendering team==0 boxes */
void EspOverlay_SetDrawHealth(BOOL draw);   /* TRUE = render health bar on ESP */
void EspOverlay_SetDrawShield(BOOL draw);   /* TRUE = render shield bar on ESP */
void EspOverlay_SetDrawDistance(BOOL draw); /* TRUE = render distance text on ESP */
void EspOverlay_SetDrawName(BOOL draw);     /* TRUE = render name text on ESP */

#ifdef __cplusplus
}
#endif

#endif /* ESP_OVERLAY_H */
