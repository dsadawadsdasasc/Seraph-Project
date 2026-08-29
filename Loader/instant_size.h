#ifndef INSTANT_SIZE_H
#define INSTANT_SIZE_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INSTANT_SIZE_DEFAULT 1 /* 1.0f normal size */

/* Enable / Disable Instant Size feature */
void InstantSize_SetEnabled(BOOL enable);
BOOL InstantSize_IsEnabled(void);

/* Set target scale integer (-1 to 2 -> -1.0f to 2.0f) */
void InstantSize_SetIntVal(int scaledVal);
int  InstantSize_GetIntVal(void);

/* Reset to default size 1.0f (val = 1) */
void InstantSize_Reset(void);

/* Tick function called from background update loop */
void InstantSize_Tick(void);

#ifdef __cplusplus
}
#endif

#endif /* INSTANT_SIZE_H */
