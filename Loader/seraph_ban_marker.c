#include "seraph_ban_marker.h"
#include "xor_strings.h"
#include "XorStr.h"
#include "debug.h"
#include <stdio.h>

#define DECODE_BM_W(arr) \
    wchar_t _dbm_##arr[sizeof(arr)/sizeof(wchar_t)]; \
    { int _wn = (int)(sizeof(arr)/sizeof(wchar_t)) - 1; \
      for (int _wi = 0; _wi < _wn; _wi++) { \
          UINT32 v0 = ((UINT32)_wi ^ SERAPH_KEY1); \
          UINT32 v1 = v0 + SERAPH_KEY2; \
          int rot = (int)((SERAPH_KEY3 + (UINT32)_wi) & 31); \
          UINT32 v2 = (v1 << rot) | (v1 >> ((32 - rot) & 31)); \
          UINT32 v3 = v2 ^ SERAPH_KEY4; \
          wchar_t kw = (wchar_t)(v3 & 0xFFFF); \
          _dbm_##arr[_wi] = (wchar_t)((arr)[_wi] ^ kw); \
      } \
      _dbm_##arr[_wn] = L'\0'; }

BOOL SeraphBanMarker_IsBanned(void) {
    /* No local storage marker on disk/registry as per user request. 
     * Always returns FALSE. Custom hardware identification is sent via Discord. */
    return FALSE;
}

void SeraphBanMarker_MarkAsBanned(void) {
    /* No-op: we do not leave any tracing file or registry key on the user's PC. */
}

void SeraphBanMarker_GetHardwareFingerprint(char* outBuf, size_t outSize) {
    if (!outBuf || outSize == 0) return;
    
    DECODE_BM_W(ENC_reg_bios_path)
    DECODE_BM_W(ENC_reg_baseboard_val)
    DECODE_BM_W(ENC_reg_systemserial_val)
    DECODE_BM_W(ENC_drive_root)

    /* 1. Read Motherboard Serial Number from Registry */
    HKEY hKey = NULL;
    char mbSerial[128] = "Unknown_MB";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, _dbm_ENC_reg_bios_path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR wMbSerial[128] = {0};
        DWORD sz = sizeof(wMbSerial);
        if (RegQueryValueExW(hKey, _dbm_ENC_reg_baseboard_val, NULL, NULL, (LPBYTE)wMbSerial, &sz) == ERROR_SUCCESS) {
            if (sz < sizeof(wMbSerial)) wMbSerial[sz / sizeof(WCHAR)] = L'\0';
            WideCharToMultiByte(CP_UTF8, 0, wMbSerial, -1, mbSerial, sizeof(mbSerial) - 1, NULL, NULL);
        } else {
            /* Fallback to SystemSerialNumber if BaseBoardSerialNumber is empty/missing */
            sz = sizeof(wMbSerial);
            if (RegQueryValueExW(hKey, _dbm_ENC_reg_systemserial_val, NULL, NULL, (LPBYTE)wMbSerial, &sz) == ERROR_SUCCESS) {
                if (sz < sizeof(wMbSerial)) wMbSerial[sz / sizeof(WCHAR)] = L'\0';
                WideCharToMultiByte(CP_UTF8, 0, wMbSerial, -1, mbSerial, sizeof(mbSerial) - 1, NULL, NULL);
            }
        }
        RegCloseKey(hKey);
    }
    mbSerial[sizeof(mbSerial) - 1] = '\0';

    /* Clean mbSerial from leading/trailing spaces */
    size_t mbLen = strlen(mbSerial);
    while (mbLen > 0 && (mbSerial[mbLen - 1] == ' ' || mbSerial[mbLen - 1] == '\r' || mbSerial[mbLen - 1] == '\n')) {
        mbSerial[--mbLen] = '\0';
    }

    /* 2. Read C: Drive Volume Serial Number */
    DWORD volSerial = 0;
    char driveRootA[8] = "C:\\";
    WideCharToMultiByte(CP_UTF8, 0, _dbm_ENC_drive_root, -1, driveRootA, sizeof(driveRootA) - 1, NULL, NULL);
    GetVolumeInformationA(driveRootA, NULL, 0, &volSerial, NULL, NULL, NULL, 0);

    /* 3. Compute unique FNV-1a hash from raw hardware inputs */
    /* Format string decoded at runtime — avoids plaintext in .rdata */
    static const char _fmtA[]={0xE8,0xE7,0x9F,0x80,0xD6,0xD9,0xF3,0xEA,0xE9,0x9F,0x80,0x95,0x9D,0xFD}; /* "MB:%s|VOL:%08X" ^0xA5 */
    char _fmtAd[15]; for(int _i=0;_i<14;_i++) _fmtAd[_i]=(char)((unsigned char)_fmtA[_i]^0xA5u); _fmtAd[14]=0;
    char rawString[512];
    _snprintf_s(rawString, sizeof(rawString), _TRUNCATE, _fmtAd, mbSerial, volSerial);

    UINT64 fnvHash = 0xCBF29CE484222325ULL;
    for (int i = 0; rawString[i]; i++) {
        fnvHash ^= (BYTE)rawString[i];
        fnvHash *= 0x00000100000001B3ULL;
    }

    /* Format output — decoded at runtime to avoid static signature */
    static const char _fmtB[]={0x80,0x95,0x94,0x93,0xEC,0x93,0x91,0xFD,0x85,0x8D,0xE8,0xE7,0x9F,0x80,0xD6,0xD9,0xF3,0xEA,0xE9,0x9F,0x80,0x95,0x9D,0xFD,0x8C}; /* "%016I64X (MB:%s|VOL:%08X)" ^0xA5 */
    char _fmtBd[26]; for(int _i=0;_i<25;_i++) _fmtBd[_i]=(char)((unsigned char)_fmtB[_i]^0xA5u); _fmtBd[25]=0;
    _snprintf_s(outBuf, outSize, _TRUNCATE, _fmtBd, fnvHash, mbSerial, volSerial);
}
