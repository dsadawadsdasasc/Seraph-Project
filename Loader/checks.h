#pragma once
#include <windows.h>
#include "seraph_secure_val.h"
/* testsigning field removed — not used in this project */
typedef struct{
    SecureVal96 hypervisor;
    SecureVal96 secureboot;
#ifdef SERAPH_BUILD_TBH
    SecureVal96 blocklist;
#endif
}SYSTEM_CHECKS;
#ifdef __cplusplus
extern "C" {
#endif

extern SYSTEM_CHECKS g_checks;
void InitializeChecks(void);
void ShowCheckUI(void);

#ifdef __cplusplus
}
#endif
