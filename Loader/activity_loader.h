#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_act_pat[];
extern const UINT8 k_act_mask[];
extern const UINT8 k_act_pat_fallback[];
extern const UINT8 k_act_mask_fallback[];

void ActivityLoader_OnAttach(void);
void ActivityLoader_OnDetach(void);
void ActivityLoader_SetActivityId(int id);
int  ActivityLoader_GetActivityId(void);
BOOL ActivityLoader_IsHooked(void);

#ifdef __cplusplus
}
#endif
