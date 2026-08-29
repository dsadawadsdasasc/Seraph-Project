#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "seraph_fuser.h"

#ifdef SERAPH_DMA_BUILD

static volatile LONG g_fuserEnabled = 0;

BOOL SeraphFuser_IsEnabled(void)
{
    return InterlockedCompareExchange(&g_fuserEnabled, 0, 0) != 0;
}

void SeraphFuser_SetEnabled(BOOL on)
{
    InterlockedExchange(&g_fuserEnabled, on ? 1 : 0);
}

#endif /* SERAPH_DMA_BUILD */
