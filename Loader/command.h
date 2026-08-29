#pragma once
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif
void ExecuteCommandSilent(LPCWSTR cmd);
void SeraphMelt(void);          /* rename + mark exe for delete on reboot */
void RelaunchAsAdmin(LPCWSTR arg);
#ifdef __cplusplus
}
#endif
