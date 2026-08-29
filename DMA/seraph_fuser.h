#pragma once
#include <windows.h>

#ifdef SERAPH_DMA_BUILD

#ifdef __cplusplus
extern "C" {
#endif

BOOL SeraphFuser_IsEnabled(void);
void SeraphFuser_SetEnabled(BOOL on);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_DMA_BUILD */
