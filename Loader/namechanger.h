#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void NameChanger_OnAttach(void);
void NameChanger_OnDetach(void);

/* Write name to cave and arm the hook. name must be UTF-8, max 31 chars. */
void NameChanger_SetName(const char *name);

void NameChanger_SetEnabled(BOOL en);
BOOL NameChanger_IsEnabled(void);
BOOL NameChanger_IsReady(void);   /* TRUE once hook installed */
void NameChanger_Tick(void);      /* call from render loop; logs addresses once */


#ifdef __cplusplus
}
#endif
