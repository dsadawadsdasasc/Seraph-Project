#pragma once
#include <windows.h>

/* Check if the local PC has been marked as banned.
 * Returns TRUE if marked, FALSE otherwise. */
BOOL SeraphBanMarker_IsBanned(void);

/* Write the inoffensive banned marker to this PC.
 * Should be called whenever a ban is triggered. */
void SeraphBanMarker_MarkAsBanned(void);

/* Retrieve hardware components (Motherboard Serial Number, BIOS Serial)
 * to build a robust local HWID/Fingerprint.
 * Fills 'outBuf' with a unique 64-character hash representing the hardware. */
void SeraphBanMarker_GetHardwareFingerprint(char* outBuf, size_t outSize);
