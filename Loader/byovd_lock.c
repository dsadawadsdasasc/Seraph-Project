/* byovd_lock.c -- Global lock for BYOVD thread safety */
#include "byovd_lock.h"

CRITICAL_SECTION g_byovdLock;

void BYOVD_LockInit(void) {
    InitializeCriticalSectionAndSpinCount(&g_byovdLock, 2000);
}

void BYOVD_LockDestroy(void) {
    DeleteCriticalSection(&g_byovdLock);
}
