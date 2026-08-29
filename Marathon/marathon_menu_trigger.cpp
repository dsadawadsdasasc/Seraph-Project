#include "seraph_menu_trigger.h"

extern "C" {

void SeraphTrigger_InitSessionToken(void) {
    // No-op for Marathon
}

BOOL SeraphTrigger_WriteToken(void) {
    return TRUE;
}

BOOL SeraphTrigger_ValidateAndConsume(void) {
    return TRUE;
}

void SeraphTrigger_OnViolationBanAndExit(void) {
    ExitProcess(0);
}

}
