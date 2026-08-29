#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(SERAPH_DMA_BUILD) && !defined(NDEBUG)
#define HS_AOB_LEN  11

extern const UINT8 k_hs_pat[];
extern const UINT8 k_hs_mask[];

void HSpeed_SetPreScanResult(UINT64 va);
void HSpeed_OnAttach(void);
BOOL HSpeed_IsReady(void);
BOOL HSpeed_IsEnabled(void);
void HSpeed_SetEnabled(BOOL state);
void HSpeed_SetMultiplier(float mult);
void HSpeed_OnDetach(void);
#else
#define HS_AOB_LEN  1
static const UINT8 k_hs_pat[1] = {0};
static const UINT8 k_hs_mask[1] = {0};

static inline void HSpeed_SetPreScanResult(UINT64 va) { (void)va; }
static inline void HSpeed_OnAttach(void) {}
static inline BOOL HSpeed_IsReady(void) { return FALSE; }
static inline BOOL HSpeed_IsEnabled(void) { return FALSE; }
static inline void HSpeed_SetEnabled(BOOL state) { (void)state; }
static inline void HSpeed_SetMultiplier(float mult) { (void)mult; }
static inline void HSpeed_OnDetach(void) {}
#endif

#ifdef __cplusplus
}
#endif
