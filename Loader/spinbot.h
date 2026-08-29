#ifndef SPINBOT_H
#define SPINBOT_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Spinbot — hooks view-direction write site, captures rdx (the float3 address),
 * then a background thread continuously randomizes those floats to spin the
 * player's view. Uses the same cave/BYOVD pattern as silent_aim / thirdperson. */

void SpinBot_SetPreScanResult(UINT64 va);
void SpinBot_OnAttach(void);
void SpinBot_OnDetach(void);
void SpinBot_SetEnabled(BOOL state);
BOOL SpinBot_IsEnabled(void);
BOOL SpinBot_IsReady(void);

#ifdef __cplusplus
}
#endif

#endif /* SPINBOT_H */
