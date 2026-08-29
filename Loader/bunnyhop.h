#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(SERAPH_DMA_BUILD) && !defined(NDEBUG)
void BunnyHop_SetEnabled(BOOL state);
BOOL BunnyHop_IsEnabled(void);

void BunnyHop_SetSpeed(float speed);
void BunnyHop_SetVertical(float vertical);

void BunnyHop_Tick(void);
#else
static inline void BunnyHop_SetEnabled(BOOL state) { (void)state; }
static inline BOOL BunnyHop_IsEnabled(void) { return FALSE; }
static inline void BunnyHop_SetSpeed(float speed) { (void)speed; }
static inline void BunnyHop_SetVertical(float vertical) { (void)vertical; }
static inline void BunnyHop_Tick(void) {}
#endif

#ifdef __cplusplus
}
#endif
