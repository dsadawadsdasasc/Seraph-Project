#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize per-session 64-bit secret trigger token */
void SeraphTrigger_InitSessionToken(void);

/* Execute memory write into .bss section variable (No VirtualAlloc) */
BOOL SeraphTrigger_WriteToken(void);

/* Validate token from .bss variable and consume it (One-Time Token).
 * Returns TRUE if valid token was written, FALSE otherwise. */
BOOL SeraphTrigger_ValidateAndConsume(void);

/* Trigger violation handler: Ban HWID/Key server-side and exit process immediately */
void SeraphTrigger_OnViolationBanAndExit(void);

#ifdef __cplusplus
}
#endif
