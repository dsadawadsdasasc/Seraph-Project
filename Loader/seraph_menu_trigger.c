#include "seraph_menu_trigger.h"
#include "keyauth.h"

/* Stealth Memory Write Trigger Target — resides in standard .bss section.
 * Zero VirtualAlloc, zero extra VAD entries created. */
static volatile UINT64 g_renderFrameState    = 0;
static UINT64          g_expectedTriggerToken = 0;
static BOOL            g_menuUnlocked         = FALSE;
static BOOL            g_sessionInited        = FALSE;

void SeraphTrigger_InitSessionToken(void) {
    if (g_sessionInited) return;

    /* Derive per-session 64-bit secret token */
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    UINT64 tick = (UINT64)GetTickCount64();

    g_expectedTriggerToken = ((UINT64)volSerial << 32) ^ tick ^ 0xA5C3F1928B4D7E20ULL;
    if (g_expectedTriggerToken == 0) g_expectedTriggerToken = 0x5D4E3F2A1B0C9D8EULL;

    g_renderFrameState = 0;
    g_menuUnlocked = FALSE;
    g_sessionInited = TRUE;
}

BOOL SeraphTrigger_WriteToken(void) {
    if (!g_sessionInited) SeraphTrigger_InitSessionToken();
    if (!g_expectedTriggerToken) return FALSE;

    /* Direct memory write into .bss static variable — no Win32 APIs involved */
    g_renderFrameState = g_expectedTriggerToken;
    return TRUE;
}

BOOL SeraphTrigger_ValidateAndConsume(void) {
#ifdef SERAPH_MARATHON
    return TRUE;
#else
    if (g_menuUnlocked) return TRUE;
    if (!g_sessionInited || !g_expectedTriggerToken) return FALSE;

    UINT64 readToken = g_renderFrameState;

    /* Check token match */
    if (readToken == g_expectedTriggerToken) {
        /* One-Time Token: Zero out memory location immediately */
        g_renderFrameState = 0;
        g_menuUnlocked = TRUE;
        return TRUE;
    }

    /* Mismatch or invalid write */
    g_renderFrameState = 0;
    return FALSE;
#endif
}

void SeraphTrigger_OnViolationBanAndExit(void) {
    /* Ban current user key/HWID server-side via KeyAuth */
    KeyAuth_BanCurrentKey();

    /* Wipe session & cleanup */
    KeyAuth_Cleanup();

    /* Immediate process termination */
    ExitProcess(0);
}
