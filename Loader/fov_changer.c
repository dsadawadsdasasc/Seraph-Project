/* fov_changer.c — Custom FOV Changer using PtrDecrypt_Decrypt
 *
 * AOB Pattern: 48 8B 3D ? ? ? ? 4C 8B F1 BD
 * Insn: mov rdi, [rip + disp32]  (7 bytes, disp32 at +3)
 * Reads encrypted camera container pointer, decrypts via PtrDecrypt_Decrypt,
 * and updates FOV float value.
 */

#include "ThemidaSDK.h"
#include "fov_changer.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "attach.h"
#include "ptr_decrypt.h"
#include "debug.h"
#include <string.h>

#define FOV_MIN_VAL  55.0f
#define FOV_MAX_VAL  155.0f
#define FOV_DEFAULT  105.0f

static UINT64 s_preScanVA = 0;
static UINT64 s_encryptedPtrVA = 0;
static BOOL   s_enabled = FALSE;
static float  s_fovVal = FOV_DEFAULT;
static DWORD  s_lastTick = 0;

static float s_originalFov = FOV_DEFAULT;
static BOOL  s_capturedOriginal = FALSE;

void FovChanger_SetPreScanResult(UINT64 va)
{
    s_preScanVA = va;
}

#include "xor_strings.h"

#pragma optimize("", off)
void FovChanger_OnAttach(void)
{
    MUTATE_START
    s_encryptedPtrVA = 0;
    s_enabled = FALSE;
    s_fovVal = FOV_DEFAULT;
    s_originalFov = FOV_DEFAULT;
    s_capturedOriginal = FALSE;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) goto _fov_end;

    UINT64 matchVA = s_preScanVA;
    if (!matchVA) {
        WriteLogFile("FovChanger: AOB not found");
        goto _fov_end;
    }


    /* 48 8B 3D [disp32] -> disp32 is at matchVA + 3 */
    INT32 disp32 = 0;
    BYOVD_LOCK();
    BYOVD_ReadVA(cr3, matchVA + 3, &disp32, 4);
    BYOVD_UNLOCK();

    if (disp32) {
        s_encryptedPtrVA = matchVA + 7 + disp32;
        char b[128];
        wsprintfA(b, "FovChanger: matchVA=0x%I64X encryptedPtrVA=0x%I64X", matchVA, s_encryptedPtrVA);
        WriteLogFile(b);

        /* Try reading initial game FOV */
        PtrDecrypt_Keys keys = {0};
        if (PtrDecrypt_ScanKeys(cr3, d2Base, &keys)) {
            UINT64 decPtr = PtrDecrypt_Decrypt(&keys, s_encryptedPtrVA, cr3);
            if (decPtr >= 0x10000ULL && decPtr < 0x7FFFFFFF0000ULL) {
                float initialVal = 0.0f;
                BYOVD_LOCK();
                BYOVD_ReadVA(cr3, decPtr + 0x15C, &initialVal, sizeof(float));
                BYOVD_UNLOCK();
                if (initialVal >= FOV_MIN_VAL && initialVal <= FOV_MAX_VAL) {
                    s_originalFov = initialVal;
                    s_fovVal = initialVal;
                    s_capturedOriginal = TRUE;
                }
            }
        }
    }

_fov_end:
    MUTATE_END
}
#pragma optimize("", on)

void FovChanger_OnDetach(void)
{
    MUTATE_START
    if (s_enabled && s_encryptedPtrVA) {
        FovChanger_SetEnabled(FALSE);
    }
    s_encryptedPtrVA = 0;
    s_enabled = FALSE;
    s_fovVal = s_originalFov;
    MUTATE_END
}

void FovChanger_SetEnabled(BOOL state)
{
    s_enabled = state;
    if (!state) {
        /* Revert to captured original game FOV */
        float revertVal = s_capturedOriginal ? s_originalFov : FOV_DEFAULT;
        UINT64 cr3 = GetDestiny2CR3();
        UINT64 d2Base = (UINT64)GetDestiny2Base();
        if (cr3 && d2Base && s_encryptedPtrVA) {
            PtrDecrypt_Keys keys = {0};
            if (PtrDecrypt_ScanKeys(cr3, d2Base, &keys)) {
                UINT64 decPtr = PtrDecrypt_Decrypt(&keys, s_encryptedPtrVA, cr3);
                if (decPtr >= 0x10000ULL && decPtr < 0x7FFFFFFF0000ULL) {
                    BYOVD_LOCK();
                    BYOVD_WriteVA(cr3, decPtr + 0x15C, &revertVal, sizeof(float));
                    BYOVD_UNLOCK();
                }
            }
        }
    }
}

BOOL FovChanger_IsEnabled(void)
{
    return s_enabled;
}

void FovChanger_SetValue(float fovVal)
{
    if (fovVal < FOV_MIN_VAL) fovVal = FOV_MIN_VAL;
    if (fovVal > FOV_MAX_VAL) fovVal = FOV_MAX_VAL;
    s_fovVal = fovVal;
}

float FovChanger_GetValue(void)
{
    return s_fovVal;
}

void FovChanger_Tick(void)
{
    if (!s_enabled || !s_encryptedPtrVA) return;

    DWORD now = GetTickCount();
    if (now - s_lastTick < 50) return;
    s_lastTick = now;

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = (UINT64)GetDestiny2Base();
    if (!cr3 || !d2Base) return;

    PtrDecrypt_Keys keys = {0};
    if (!PtrDecrypt_ScanKeys(cr3, d2Base, &keys)) return;

    UINT64 decPtr = PtrDecrypt_Decrypt(&keys, s_encryptedPtrVA, cr3);
    if (decPtr < 0x10000ULL || decPtr >= 0x7FFFFFFF0000ULL) return;

    /* Capture original game FOV if not yet captured */
    if (!s_capturedOriginal && !s_enabled) {
        float gameVal = 0.0f;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, decPtr + 0x15C, &gameVal, sizeof(float));
        BYOVD_UNLOCK();
        if (gameVal >= FOV_MIN_VAL && gameVal <= FOV_MAX_VAL) {
            s_originalFov = gameVal;
            s_fovVal = gameVal;
            s_capturedOriginal = TRUE;
        }
    }

    if (!s_enabled) return;

    float currVal = 0.0f;
    BYOVD_LOCK();
    if (!BYOVD_ReadVA(cr3, decPtr + 0x15C, &currVal, sizeof(float)) || currVal != s_fovVal) {
        BYOVD_WriteVA(cr3, decPtr + 0x15C, &s_fovVal, sizeof(float));
    }
    BYOVD_UNLOCK();
}
