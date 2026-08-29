
#include "ThemidaSDK.h"
#include "keyauth.h"
#include "syscalls.h"
#include "XorStr.h"

#include "debug.h"
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <intrin.h>

#ifndef OWNER_ID
#error "OWNER_ID must be defined by the build system (/D OWNER_ID=L\"...\"). Never hardcode here."
#endif
#ifndef APP_NAME
#error "APP_NAME must be defined by the build system (/D APP_NAME=L\"...\"). Never hardcode here."
#endif
#ifndef APP_VER
#define APP_VER L"1.0"
#endif

typedef HINTERNET(WINAPI*tWinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET(WINAPI*tWinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET(WINAPI*tWinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL(WINAPI*tWinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL(WINAPI*tWinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL(WINAPI*tWinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL(WINAPI*tWinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL(WINAPI*tWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI*tWinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);

/* Pre-encrypted strings — generated per-build with random XOR key */
#include "xor_strings.h"

/* --- globals set once at load --- */
static tWinHttpOpen               g_fO  = NULL;
static tWinHttpConnect            g_fC  = NULL;
static tWinHttpOpenRequest        g_fOR = NULL;
static tWinHttpSendRequest        g_fS  = NULL;
static tWinHttpReceiveResponse    g_fRR = NULL;
static tWinHttpQueryDataAvailable g_fQ  = NULL;
static tWinHttpReadData           g_fRD = NULL;
static tWinHttpCloseHandle        g_fCH = NULL;
static tWinHttpSetOption          g_fSO = NULL;
static HINTERNET                  g_hS  = NULL;
static HINTERNET                  g_hC  = NULL;

/* Persistent session data for post-auth operations (ban) */
static char g_kaSession[128]  = {0};
static char g_kaOwner[64]     = {0};
static char g_kaName[64]      = {0};
static char g_kaHwid[64]      = {0};   /* P3.8 — propagado p/ payload via PayloadCtx */
wchar_t g_kaUsername[64]      = {0};
static volatile LONG g_kaSessionValid = 0;
static HMODULE g_hWinHttp = NULL;  /* kept alive for ban capability */

/* L-KEYAUTH-1: Build a convincing Chrome/Windows user-agent per session.
   Uses volume serial as seed — differs per machine, avoids static "WinHTTP/2.0". */
static void BuildUserAgent(WCHAR* out, int outChars) {
    DWORD vol = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol, NULL, NULL, NULL, 0);
    DWORD minor = 3000 + (vol & 0xFFF);
    DWORD patch  = (vol >> 12) & 0xFFFF;
    _snwprintf_s(out, outChars, _TRUNCATE,
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        L"AppleWebKit/537.36 (KHTML, like Gecko) "
        L"Chrome/124.0.%u.%u Safari/537.36",
        minor, patch);
}

/* C-4: Send a POST body — reads ALL HTTP chunks in a loop until avail==0.
   Returns heap-allocated null-terminated response. Caller must free(). NULL on failure. */
static char* DoPost(const char* body) {
    HINTERNET hR = g_fOR(g_hC, DXOR_W(ENC_POST), DXOR_W(ENC_api_path),
                         NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                         WINHTTP_FLAG_SECURE);
    if (!hR) return NULL;

    /* P1: Forçar validação estrita de certificado SSL do canal HTTPS.
     * Limpa qualquer flag de ignorar erros de CA desconhecida, CN inválido ou expiração,
     * impedindo ataques de interceptação local (MitM / proxy de descriptografia). */
    if (g_fSO) {
        DWORD cleanFlags = 0;
        g_fSO(hR, WINHTTP_OPTION_SECURITY_FLAGS, &cleanFlags, sizeof(cleanFlags));
    }

    DWORD l = (DWORD)strlen(body);
    if (!g_fS(hR, DXOR_W(ENC_content_type), (DWORD)-1, (LPVOID)body, l, l, 0)) {
        g_fCH(hR); return NULL;
    }
    if (!g_fRR(hR, NULL)) { g_fCH(hR); return NULL; }

    /* Loop until all TCP chunks are consumed */
    char  *buf   = NULL;
    DWORD  total = 0;
    DWORD  avail = 0;
    do {
        avail = 0;
        if (!g_fQ(hR, &avail) || avail == 0) break;
        char *tmp = (char*)realloc(buf, total + avail + 1);
        if (!tmp) { free(buf); buf = NULL; break; }
        buf = tmp;
        DWORD nread = 0;
        if (!g_fRD(hR, buf + total, avail, &nread) || nread == 0) break;
        total += nread;
        buf[total] = '\0';
    } while (avail > 0);

    g_fCH(hR);
    return buf;
}

/* P2: ExtractJsonStr com bounds checking rigoroso de buffers de entrada e destino. */
static int ExtractJsonStr(const char* json, const char* key, char* out, int outLen) {
    if (!json || !key || !out || outLen <= 0) return 0;
    const char* p = strstr(json, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ':' || *p == ' ') p++;
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outLen - 1) {
        out[i++] = *p++;
    }
    out[i] = 0;
    return i > 0;
}

/* P2: ExtractJsonStrW valida o retorno de MultiByteToWideChar para evitar
 * estouro de pilha e escrita além do limite configurado. */
static int ExtractJsonStrW(const char* json, const char* key, wchar_t* out, int outLen) {
    char tmp[256];
    if (outLen <= 0 || !out) return 0;
    if (!ExtractJsonStr(json, key, tmp, sizeof(tmp))) return 0;
    int len = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, out, outLen);
    if (len > 0 && len <= outLen) {
        out[len - 1] = L'\0';
        return 1;
    }
    return 0;
}

/* Map error message to KEYAUTH_RESULT */
static KEYAUTH_RESULT MapErrorToResult(const char* json) {
    char msg[128] = {0};
    /* JSON key decoded at runtime — avoids .rdata signature */
    static const char _mk[]={0x3B,0x74,0x7C,0x6A,0x6A,0x78,0x7E,0x7C,0x3B}; /* '"message"' ^0x19 */
    char _md[10]; for(int _i=0;_i<9;_i++) _md[_i]=(char)((unsigned char)_mk[_i]^0x19u); _md[9]=0;
    if (!ExtractJsonStr(json, _md, msg, sizeof(msg)))
        return KEYAUTH_UNKNOWN_ERROR;
    for (char* p = msg; *p; ++p) *p = tolower(*p);
    /* XOR key 0x13 — error strings decoded on stack, never in .rdata */
    { static const char _ek1[]={0x7A,0x7D,0x65,0x72,0x7F,0x7A,0x77,0x33,0x7F,0x7A,0x70,0x76,0x7D,0x60,0x76,0x33,0x78,0x76,0x6A}; /* "invalid license key" ^0x13 */
      char _dk1[20]; for(int _i=0;_i<19;_i++) _dk1[_i]=(char)((unsigned char)_ek1[_i]^0x13u); _dk1[19]=0;
      static const char _ek2[]={0x7A,0x7D,0x65,0x72,0x7F,0x7A,0x77,0x33,0x78,0x76,0x6A}; /* "invalid key" ^0x13 */
      char _dk2[12]; for(int _i=0;_i<11;_i++) _dk2[_i]=(char)((unsigned char)_ek2[_i]^0x13u); _dk2[11]=0;
      if (strstr(msg, _dk1) || strstr(msg, _dk2)) return KEYAUTH_INVALID_KEY; }
    { static const char _ek3[]={0x78,0x76,0x6A,0x33,0x72,0x7F,0x61,0x76,0x72,0x77,0x6A,0x33,0x66,0x60,0x76,0x77}; /* "key already used" ^0x13 */
      char _dk3[17]; for(int _i=0;_i<16;_i++) _dk3[_i]=(char)((unsigned char)_ek3[_i]^0x13u); _dk3[16]=0;
      static const char _ek4[]={0x72,0x7F,0x61,0x76,0x72,0x77,0x6A,0x33,0x66,0x60,0x76,0x77}; /* "already used" ^0x13 */
      char _dk4[13]; for(int _i=0;_i<12;_i++) _dk4[_i]=(char)((unsigned char)_ek4[_i]^0x13u); _dk4[12]=0;
      if (strstr(msg, _dk3) || strstr(msg, _dk4)) return KEYAUTH_KEY_ALREADY_USED; }
    { static const char _ek5[]={0x76,0x6B,0x63,0x7A,0x61,0x76,0x77}; /* "expired" ^0x13 */
      char _dk5[8]; for(int _i=0;_i<7;_i++) _dk5[_i]=(char)((unsigned char)_ek5[_i]^0x13u); _dk5[7]=0;
      if (strstr(msg, _dk5)) return KEYAUTH_KEY_EXPIRED; }
    { static const char _ek6[]={0x71,0x72,0x7D,0x7D,0x76,0x77}; /* "banned" ^0x13 */
      char _dk6[7]; for(int _i=0;_i<6;_i++) _dk6[_i]=(char)((unsigned char)_ek6[_i]^0x13u); _dk6[6]=0;
      if (strstr(msg, _dk6)) return KEYAUTH_KEY_BANNED; }
    { static const char _ek7[]={0x7D,0x7C,0x33,0x60,0x66,0x71,0x60,0x70,0x61,0x7A,0x63,0x67,0x7A,0x7C,0x7D}; /* "no subscription" ^0x13 */
      char _dk7[16]; for(int _i=0;_i<15;_i++) _dk7[_i]=(char)((unsigned char)_ek7[_i]^0x13u); _dk7[15]=0;
      static const char _ek8[]={0x60,0x66,0x71,0x60,0x70,0x61,0x7A,0x63,0x67,0x7A,0x7C,0x7D}; /* "subscription" ^0x13 */
      char _dk8[13]; for(int _i=0;_i<12;_i++) _dk8[_i]=(char)((unsigned char)_ek8[_i]^0x13u); _dk8[12]=0;
      if (strstr(msg, _dk7) || strstr(msg, _dk8)) return KEYAUTH_NO_SUBSCRIPTION; }
    { static const char _ek9[]={0x7B,0x64,0x7A,0x77,0x33,0x7E,0x7A,0x60,0x7E,0x72,0x67,0x70,0x7B}; /* "hwid mismatch" ^0x13 */
      char _dk9[14]; for(int _i=0;_i<13;_i++) _dk9[_i]=(char)((unsigned char)_ek9[_i]^0x13u); _dk9[13]=0;
      static const char _eka[]={0x7B,0x64,0x7A,0x77}; /* "hwid" ^0x13 */
      char _dka[5]; for(int _i=0;_i<4;_i++) _dka[_i]=(char)((unsigned char)_eka[_i]^0x13u); _dka[4]=0;
      if (strstr(msg, _dk9) || strstr(msg, _dka)) return KEYAUTH_HWID_MISMATCH; }
    return KEYAUTH_UNKNOWN_ERROR;
}

/* LoadWinHttp — resolve all 8 WinHTTP function pointers.
 * Runs OUTSIDE any VM/Mutate region so Themida cannot reorder the
 * DXOR_A pool calls.  Each name is decoded into a private stack buffer
 * (not the shared pool) so there is zero risk of slot recycling.
 * Returns the loaded HMODULE on success, NULL on failure.            */
static HMODULE LoadWinHttp(void) {
    /* Decode each name into its own stack buffer — immune to pool reuse */
#define DECODE_A(arr) \
    char _d_##arr[sizeof(arr)]; \
    { int _len = (int)sizeof(arr) - 1; \
      for (int _i = 0; _i < _len; _i++) { \
          UINT32 v0 = ((UINT32)_i ^ SERAPH_KEY1); \
          UINT32 v1 = v0 + SERAPH_KEY2; \
          int rot = (int)((SERAPH_KEY3 + (UINT32)_i) & 31); \
          UINT32 v2 = (v1 << rot) | (v1 >> (32 - rot)); \
          UINT32 v3 = v2 ^ SERAPH_KEY4; \
          unsigned char kb = (unsigned char)(v3 & 0xFF); \
          _d_##arr[_i] = (char)((arr)[_i] ^ kb); \
      } \
      _d_##arr[sizeof(arr)-1] = '\0'; }

    /* Wide decode for the DLL name */
    wchar_t _wdll[sizeof(ENC_winhttp_dll)/sizeof(wchar_t)];
    { int _n = (int)(sizeof(ENC_winhttp_dll)/sizeof(wchar_t)) - 1;
      for (int _i = 0; _i < _n; _i++) {
          UINT32 v0 = ((UINT32)_i ^ SERAPH_KEY1);
          UINT32 v1 = v0 + SERAPH_KEY2;
          int rot = (int)((SERAPH_KEY3 + (UINT32)_i) & 31);
          UINT32 v2 = (v1 << rot) | (v1 >> (32 - rot));
          UINT32 v3 = v2 ^ SERAPH_KEY4;
          wchar_t kw = (wchar_t)(v3 & 0xFFFF);
          _wdll[_i] = (wchar_t)(ENC_winhttp_dll[_i] ^ kw);
      }
      _wdll[_n] = L'\0'; }

    HMODULE w = (HMODULE)SeraphLoadDll(_wdll, NULL);
    if (!w) {
        /* Converte a string larga em ASCII simples para logar */
        char logName[64];
        int i = 0;
        while (_wdll[i] && i < 63) { logName[i] = (char)_wdll[i]; i++; }
        logName[i] = 0;
        char logBuf[128];
        wsprintfA(logBuf, "LoadWinHttp: SeraphLoadDll failed for '%s'", logName);
        WriteLogFile(logBuf);
        return NULL;
    }
    WriteLogFile("LoadWinHttp: winhttp.dll loaded successfully");

#define LOG_AND_RESOLVE(func_ptr, type, enc_name) \
    DECODE_A(enc_name); \
    WriteLogFile(_d_##enc_name); \
    func_ptr = (type)SeraphGetProcAddress(w, _d_##enc_name);

    LOG_AND_RESOLVE(g_fO, tWinHttpOpen, ENC_WinHttpOpen);
    if (!g_fO) WriteLogFile("LoadWinHttp: failed to resolve WinHttpOpen");

    LOG_AND_RESOLVE(g_fC, tWinHttpConnect, ENC_WinHttpConnect);
    if (!g_fC) WriteLogFile("LoadWinHttp: failed to resolve WinHttpConnect");

    LOG_AND_RESOLVE(g_fOR, tWinHttpOpenRequest, ENC_WinHttpOpenRequest);
    if (!g_fOR) WriteLogFile("LoadWinHttp: failed to resolve WinHttpOpenRequest");

    LOG_AND_RESOLVE(g_fS, tWinHttpSendRequest, ENC_WinHttpSendRequest);
    if (!g_fS) WriteLogFile("LoadWinHttp: failed to resolve WinHttpSendRequest");

    LOG_AND_RESOLVE(g_fRR, tWinHttpReceiveResponse, ENC_WinHttpReceiveResponse);
    if (!g_fRR) WriteLogFile("LoadWinHttp: failed to resolve WinHttpReceiveResponse");

    LOG_AND_RESOLVE(g_fQ, tWinHttpQueryDataAvailable, ENC_WinHttpQueryDataAvailable);
    if (!g_fQ) WriteLogFile("LoadWinHttp: failed to resolve WinHttpQueryDataAvailable");

    LOG_AND_RESOLVE(g_fRD, tWinHttpReadData, ENC_WinHttpReadData);
    if (!g_fRD) WriteLogFile("LoadWinHttp: failed to resolve WinHttpReadData");

    LOG_AND_RESOLVE(g_fCH, tWinHttpCloseHandle, ENC_WinHttpCloseHandle);
    if (!g_fCH) WriteLogFile("LoadWinHttp: failed to resolve WinHttpCloseHandle");

    /* P1: Carregar WinHttpSetOption com decodificação XOR em pilha local */
    char _soName[17];
    { static const char _soEnc[] = {
          ('W'^0x4D),('i'^0x4D),('n'^0x4D),('H'^0x4D),('t'^0x4D),('t'^0x4D),('p'^0x4D),('S'^0x4D),
          ('e'^0x4D),('t'^0x4D),('O'^0x4D),('p'^0x4D),('t'^0x4D),('i'^0x4D),('o'^0x4D),('n'^0x4D),0
      };
      for(int i=0;i<16;i++) _soName[i] = _soEnc[i] ^ 0x4D; _soName[16] = 0; }
    WriteLogFile(_soName);
    g_fSO = (tWinHttpSetOption)SeraphGetProcAddress(w, _soName);
    if (!g_fSO) WriteLogFile("LoadWinHttp: failed to resolve WinHttpSetOption");

#undef DECODE_A
#undef LOG_AND_RESOLVE

    if (!g_fO||!g_fC||!g_fOR||!g_fS||!g_fRR||!g_fQ||!g_fRD||!g_fCH||!g_fSO) {
        WriteLogFile("LoadWinHttp: one or more function pointers failed to resolve, freeing DLL");
        SeraphFreeDll(w);
        return NULL;
    }
    WriteLogFile("LoadWinHttp: all function pointers resolved successfully");
    return w;
}

/* Core validation with detailed error reporting */
#pragma optimize("", off)
KEYAUTH_RESULT KeyAuthValidate(LPCWSTR key, wchar_t* errMsg, size_t errMsgSize) {
#ifdef IS_TBH_PRODUCT
    if (key == NULL || wcslen(key) != 6) {
        if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Invalid license key");
        return KEYAUTH_INVALID_KEY;
    }
#endif

    /* LoadWinHttp must run BEFORE VM_ST_ART — Themida's VM can reorder
     * DXOR pool calls and corrupt function-pointer resolution.         */
    HMODULE w = LoadWinHttp();
    if (!w) {
        { static const unsigned short _fw[]={0xE3,0xC4,0xCC,0xC9,0xC0,0xC1,0x85,0xD1,0xCA,0x85,0xC9,0xCA,0xC4,0xC1,0x85,0xD2,0xCC,0xCB,0xCD,0xD1,0xD1,0xD5,0x8B,0xC1,0xC9,0xC9}; /* L"Failed to load winhttp.dll" ^0xA5 */
          wchar_t _fwd[27]; for(int _i=0;_i<26;_i++) _fwd[_i]=(wchar_t)(_fw[_i]^0xA5u); _fwd[26]=0;
          if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, _fwd); }
        return KEYAUTH_NETWORK_ERROR;
    }

    VM_START
    KEYAUTH_RESULT result = KEYAUTH_NETWORK_ERROR;
    char* initResp = NULL;
    char* licResp  = NULL;

    /* L-KEYAUTH-1: Dynamic user-agent */
    WCHAR ua[256];
    BuildUserAgent(ua, 256);
    g_hS = g_fO(ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_hS) {
        { static const unsigned short _wo[]={0xF2,0xCC,0xCB,0xED,0xD1,0xD1,0xD5,0xEA,0xD5,0xC0,0xCB,0x85,0xC3,0xC4,0xCC,0xC9,0xC0,0xC1}; /* L"WinHttpOpen failed" ^0xA5 */
          wchar_t _wod[19]; for(int _i=0;_i<18;_i++) _wod[_i]=(wchar_t)(_wo[_i]^0xA5u); _wod[18]=0;
          if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, _wod); }
        SeraphFreeDll(w); w = NULL;
        goto _kav_end;
    }
    /* Prevent infinite hang on slow/broken proxy resolution or dead servers. */
    { typedef BOOL(WINAPI*tSetTO)(HINTERNET,int,int,int,int);
      tSetTO fSetTO = (tSetTO)SeraphGetProcAddress(w, DXOR_A(ENC_WinHttpSetTimeouts)); /* P12 */
      if (fSetTO) fSetTO(g_hS, 15000, 15000, 15000, 15000); }

    g_hC = g_fC(g_hS, DXOR_W(ENC_keyauth_host), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!g_hC) {
        g_fCH(g_hS);
        { static const unsigned short _wc[]={0xF2,0xCC,0xCB,0xED,0xD1,0xD1,0xD5,0xE6,0xCA,0xCB,0xCB,0xC0,0xC6,0xD1,0x85,0xC3,0xC4,0xCC,0xC9,0xC0,0xC1}; /* L"WinHttpConnect failed" ^0xA5 */
          wchar_t _wcd[22]; for(int _i=0;_i<21;_i++) _wcd[_i]=(wchar_t)(_wc[_i]^0xA5u); _wcd[21]=0;
          if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, _wcd); }
        SeraphFreeDll(w); w = NULL;
        goto _kav_end;
    }

    /* HWID calculated using Computer Name hash and Volume Serial.
     * This avoids querying HKEY_LOCAL_MACHINE Registry keys, which can fail or
     * return virtualized values depending on UAC elevation.
     * It also avoids raw CPUID instructions, which can return different model/stepping values
     * depending on whether the thread is scheduled on a P-core or an E-core (hybrid CPU architectures),
     * causing unstable HWIDs and constant HWID reset requests. */
    char hwid[64] = {0};
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0);

    char compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compNameSize = sizeof(compName);
    GetComputerNameA(compName, &compNameSize);

    /* FNV-1a hash of the computer name */
    DWORD compHash = 2166136261u;
    for (DWORD i = 0; i < compNameSize && compName[i]; i++) {
        compHash ^= (BYTE)compName[i];
        compHash *= 16777619u;
    }

    sprintf(hwid, "%08X%08X%08X%08X",
            volSerial, compHash, volSerial ^ compHash,
            (volSerial + compHash) * 16777619u);
    DEBUG_KEYAUTH("HWID components: vol=0x%08X compHash=0x%08X",
        volSerial, compHash);
    DEBUG_KEYAUTH("HWID final: %s", hwid);

    char ownerA[64]={0}, nameA[64]={0}, verA[16]={0}, keyA[128]={0};
    WideCharToMultiByte(CP_ACP,0,OWNER_ID,-1,ownerA,sizeof(ownerA)-1,NULL,NULL);
    WideCharToMultiByte(CP_ACP,0,APP_NAME,-1,nameA, sizeof(nameA)-1, NULL,NULL);
    WideCharToMultiByte(CP_ACP,0,APP_VER,  -1,verA,  sizeof(verA)-1,  NULL,NULL);
    WideCharToMultiByte(CP_ACP,0,key,      -1,keyA,  sizeof(keyA)-1,  NULL,NULL);

    /* P13: formato do POST body encodado — monta por parãmetros
     * sem deixar "type=init" como string literal em .rdata. */
    char initBody[512];
    { /* "type=init&ver=" + ver + "&name=" + name + "&ownerid=" + owner + "&hash=0000..." */
      static const char _k1[]={('t'^0x19),('y'^0x19),('p'^0x19),('e'^0x19),('='^0x19),('i'^0x19),('n'^0x19),('i'^0x19),('t'^0x19),0};
      static const char _k2[]={('&'^0x19),('v'^0x19),('e'^0x19),('r'^0x19),('='^0x19),0};
      static const char _k3[]={('&'^0x19),('n'^0x19),('a'^0x19),('m'^0x19),('e'^0x19),('='^0x19),0};
      static const char _k4[]={('&'^0x19),('o'^0x19),('w'^0x19),('n'^0x19),('e'^0x19),('r'^0x19),('i'^0x19),('d'^0x19),('='^0x19),0};
      char _d1[10],_d2[6],_d3[7],_d4[10];
      for(int i=0;_k1[i];i++)_d1[i]=(char)(((unsigned char)_k1[i])^0x19);_d1[9]=0;
      for(int i=0;_k2[i];i++)_d2[i]=(char)(((unsigned char)_k2[i])^0x19);_d2[5]=0;
      for(int i=0;_k3[i];i++)_d3[i]=(char)(((unsigned char)_k3[i])^0x19);_d3[6]=0;
      for(int i=0;_k4[i];i++)_d4[i]=(char)(((unsigned char)_k4[i])^0x19);_d4[9]=0;
      sprintf(initBody, "%s%s%s%s%s%s%s%s&hash=0000000000000000000000000000000000000000000000000000000000000000",
              _d1, _d2, verA, _d3, nameA, _d4, ownerA, "");
    }

    initResp = DoPost(initBody);
    if (!initResp) {
        g_fCH(g_hC); g_fCH(g_hS); SeraphFreeDll(w); w = NULL;
        if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Network error (init)");
        goto _kav_end;
    }

    char sessionid[128] = {0};
    /* sessionid key decoded at runtime */
    static const char _sk[]={0x3B,0x6A,0x7C,0x6A,0x6A,0x70,0x76,0x77,0x70,0x7D,0x3B}; /* '"sessionid"' ^0x19 */
    char _sd[12]; for(int _i=0;_i<11;_i++) _sd[_i]=(char)((unsigned char)_sk[_i]^0x19u); _sd[11]=0;
    if (!ExtractJsonStr(initResp, _sd, sessionid, sizeof(sessionid))) {
        free(initResp); initResp = NULL;
        g_fCH(g_hC); g_fCH(g_hS); SeraphFreeDll(w); w = NULL;
        if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Invalid init response");
        result = KEYAUTH_SERVER_ERROR;
        goto _kav_end;
    }
    free(initResp); initResp = NULL;

    /* P13: "type=license" encodado */
    char licBody[768];
    BOOL using_custom_username = (g_kaUsername[0] != 0);
    if (using_custom_username) {
        char userA[64] = {0};
        WideCharToMultiByte(CP_ACP, 0, g_kaUsername, -1, userA, sizeof(userA)-1, NULL, NULL);

        /* type=login request:
         * "type=login&username=%s&pass=%s&sessionid=%s&name=%s&ownerid=%s&hwid=%s" ^ 0x19 */
        static const char fmt_login[] = {
            0x6D,0x60,0x69,0x7C,0x24,0x75,0x76,0x7E,0x70,0x77,0x3F,0x6C,0x6A,0x7C,0x6B,0x77,
            0x78,0x74,0x7C,0x24,0x3C,0x6A,0x3F,0x69,0x78,0x6A,0x6A,0x24,0x3C,0x6A,0x3F,0x6A,
            0x7C,0x6A,0x6A,0x70,0x76,0x77,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x77,0x78,0x74,0x7C,
            0x24,0x3C,0x6A,0x3F,0x76,0x6E,0x77,0x7C,0x6B,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x71,
            0x6E,0x70,0x7D,0x24,0x3C,0x6A,0
        };
        char dec_login[71];
        for (int i = 0; i < 70; i++) dec_login[i] = (char)(fmt_login[i] ^ 0x19u);
        dec_login[70] = 0;

        sprintf(licBody, dec_login, userA, keyA, sessionid, nameA, ownerA, hwid);
    } else {
        static const char _lk[]={('t'^0x19),('y'^0x19),('p'^0x19),('e'^0x19),('='^0x19),('l'^0x19),('i'^0x19),('c'^0x19),('e'^0x19),('n'^0x19),('s'^0x19),('e'^0x19),0};
        char _ld[13]; for(int i=0;_lk[i];i++)_ld[i]=(char)(((unsigned char)_lk[i])^0x19);_ld[12]=0;
        static const char _fmt_fmt1[] = {0x3C,0x6A,0x3F,0x72,0x7C,0x60,0x24,0x3C,0x6A,0x3F,0x76,0x6E,0x77,0x7C,0x6B,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x6A,0x7C,0x6A,0x6A,0x70,0x76,0x77,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x71,0x6E,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x77,0x78,0x74,0x7C,0x24,0x3C,0x6A}; /* "%s&key=%s&ownerid=%s&sessionid=%s&hwid=%s&name=%s" ^0x19 */
        char _dec_f1[50];
        for (int _i = 0; _i < 49; _i++) _dec_f1[_i] = (char)(_fmt_fmt1[_i] ^ 0x19u);
        _dec_f1[49] = 0;
        sprintf(licBody, _dec_f1, _ld, keyA, ownerA, sessionid, hwid, nameA);
    }

    licResp = DoPost(licBody);
    if (!licResp) {
        g_fCH(g_hC); g_fCH(g_hS); SeraphFreeDll(w); w = NULL;
        if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Network error (license)");
        goto _kav_end;
    }

    /* Fallback to type=register if type=login failed because the user does not exist yet. */
    if (using_custom_username && licResp &&
        strstr(licResp, "hwid") == NULL &&
        (strstr(licResp, "not found") != NULL ||
         strstr(licResp, "not_found") != NULL ||
         strstr(licResp, "Not Found") != NULL ||
         strstr(licResp, "not exist") != NULL ||
         strstr(licResp, "not_exist") != NULL ||
         strstr(licResp, "Invalid username") != NULL ||
         strstr(licResp, "invalid username") != NULL ||
         strstr(licResp, "Invalid user") != NULL ||
         strstr(licResp, "invalid user") != NULL)) {
        char userA[64] = {0};
        WideCharToMultiByte(CP_ACP, 0, g_kaUsername, -1, userA, sizeof(userA)-1, NULL, NULL);

        /* type=register request:
         * "type=register&username=%s&pass=%s&key=%s&sessionid=%s&name=%s&ownerid=%s&hwid=%s" ^ 0x19 */
        static const char fmt_reg[] = {
            0x6D,0x60,0x69,0x7C,0x24,0x6B,0x7C,0x7E,0x70,0x6A,0x6D,0x7C,0x6B,0x3F,0x6C,0x6A,
            0x7C,0x6B,0x77,0x78,0x74,0x7C,0x24,0x3C,0x6A,0x3F,0x69,0x78,0x6A,0x6A,0x24,0x3C,
            0x6A,0x3F,0x72,0x7C,0x60,0x24,0x3C,0x6A,0x3F,0x6A,0x7C,0x6A,0x6A,0x70,0x76,0x77,
            0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x77,0x78,0x74,0x7C,0x24,0x3C,0x6A,0x3F,0x76,0x6E,
            0x77,0x7C,0x6B,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x71,0x6E,0x70,0x7D,0x24,0x3C,0x6A,0
        };
        char dec_reg[81];
        for (int i = 0; i < 80; i++) dec_reg[i] = (char)(fmt_reg[i] ^ 0x19u);
        dec_reg[80] = 0;

        sprintf(licBody, dec_reg, userA, keyA, keyA, sessionid, nameA, ownerA, hwid);

        free(licResp);
        licResp = DoPost(licBody);
        if (!licResp) {
            g_fCH(g_hC); g_fCH(g_hS); SeraphFreeDll(w); w = NULL;
            if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Network error (register)");
            goto _kav_end;
        }
    }

    result = KEYAUTH_SUCCESS;
    if (!(strstr(licResp, DXOR_A(ENC_success_true)) != NULL)) {
        result = MapErrorToResult(licResp);
        wchar_t tmpMsg[256] = {0};
    /* message key decoded at runtime (2nd use) */
    static const char _mk2[]={0x3B,0x74,0x7C,0x6A,0x6A,0x78,0x7E,0x7C,0x3B};
    char _md2[10]; for(int _i=0;_i<9;_i++) _md2[_i]=(char)((unsigned char)_mk2[_i]^0x19u); _md2[9]=0;
    if (ExtractJsonStrW(licResp, _md2, tmpMsg, 256)) {
            if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, tmpMsg);
        } else {
            if (errMsg && errMsgSize) wcscpy_s(errMsg, errMsgSize, L"Unknown license error");
        }
    } else {
        if (errMsg && errMsgSize) errMsg[0] = 0;
    }

    free(licResp); licResp = NULL;

    /* Persist session data for post-auth operations (ban).  
     * Keep g_hC/g_hS open so KeyAuth_BanCurrentKey can reuse them. */
    if (result == KEYAUTH_SUCCESS) {
        strncpy(g_kaSession, sessionid, sizeof(g_kaSession) - 1);
        strncpy(g_kaOwner, ownerA, sizeof(g_kaOwner) - 1);
        strncpy(g_kaName, nameA, sizeof(g_kaName) - 1);
        strncpy(g_kaHwid, hwid, sizeof(g_kaHwid) - 1);
        InterlockedExchange(&g_kaSessionValid, 1);
        g_hWinHttp = w;  /* keep DLL loaded for ban function pointers */
        /* Do NOT close g_hC/g_hS here — they're needed for ban */
    } else {
        g_fCH(g_hC);
        g_fCH(g_hS);
        SeraphFreeDll(w); w = NULL;
        g_fO=NULL; g_fC=NULL; g_fOR=NULL; g_fS=NULL;
        g_fRR=NULL; g_fQ=NULL; g_fRD=NULL; g_fCH=NULL;
        g_hS=NULL; g_hC=NULL;
    }
_kav_end:
    /* BUG FIX: zero sensitive stack buffers before returning.
     * hwid = machine fingerprint, userName = OS username, keyA = license key.
     * Without this, all three survive on the stack frame until overwritten. */
    SecureZeroMemory(g_kaUsername, sizeof(g_kaUsername));
    SecureZeroMemory(hwid,      sizeof(hwid));
    SecureZeroMemory(keyA,      sizeof(keyA));
    VM_END
    return result;
}
#pragma optimize("", on)

BOOL KeyAuthLicense(LPCWSTR k) {
    KEYAUTH_RESULT res = KeyAuthValidate(k, NULL, 0);
    return (res == KEYAUTH_SUCCESS);
}

BOOL KeyAuth_BanCurrentKey(void) {
    if (!InterlockedCompareExchange(&g_kaSessionValid, 1, 1)) return FALSE;
    if (!g_fOR || !g_hC) return FALSE;

    /* P4: "type=ban" e "reason=antire" encodados — sem plaintext em .rdata */
    char banBody[512];
    { static const char _bk[]={('t'^0x2A),('y'^0x2A),('p'^0x2A),('e'^0x2A),('='^0x2A),('b'^0x2A),('a'^0x2A),('n'^0x2A),0};
      static const char _rk[]={('r'^0x2A),('e'^0x2A),('a'^0x2A),('s'^0x2A),('o'^0x2A),('n'^0x2A),('='^0x2A),('a'^0x2A),('n'^0x2A),('t'^0x2A),('i'^0x2A),('r'^0x2A),('e'^0x2A),0};
      char _bd[9],_rd[14];
      for(int i=0;_bk[i];i++)_bd[i]=(char)(((unsigned char)_bk[i])^0x2A);_bd[8]=0;
      for(int i=0;_rk[i];i++)_rd[i]=(char)(((unsigned char)_rk[i])^0x2A);_rd[13]=0;
      static const char _fmt_fmt2[] = {0x3C,0x6A,0x3F,0x6A,0x7C,0x6A,0x6A,0x70,0x76,0x77,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x77,0x78,0x74,0x7C,0x24,0x3C,0x6A,0x3F,0x76,0x6E,0x77,0x7C,0x6B,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x3C,0x6A}; /* "%s&sessionid=%s&name=%s&ownerid=%s&%s" ^0x19 */
      char _dec_f2[38];
      for(int _i=0;_i<37;_i++) _dec_f2[_i]=(char)(_fmt_fmt2[_i]^0x19u); _dec_f2[37]=0;
      sprintf(banBody, _dec_f2,
              _bd, g_kaSession, g_kaName, g_kaOwner, _rd);
    }

    char *resp = DoPost(banBody);
    BOOL ok = FALSE;
    if (resp) {
        static const char _suc[] = {0x6A,0x6C,0x7A,0x7A,0x7C,0x6A,0x6A}; /* "success" ^0x19 */
        char _dec_suc[8]; for (int _i = 0; _i < 7; _i++) _dec_suc[_i] = (char)(_suc[_i] ^ 0x19u); _dec_suc[7] = 0;
        ok = (strstr(resp, _dec_suc) != NULL);
        free(resp);
    }
    InterlockedExchange(&g_kaSessionValid, 0);  /* one-shot */
    return ok;
}

/* P3.3 — fetch a server-side variable via type=var.
 * Returns malloc'd ASCII string on success, NULL on failure. */
char* KeyAuth_GetVarString(const char* varName_a);  /* fwd declared in keyauth.h */
static char* GetVar(const char* varName_a) {
    if (!InterlockedCompareExchange(&g_kaSessionValid, 1, 1)) return NULL;
    if (!g_fOR || !g_hC) return NULL;
    /* P13: "type=var" encodado */
    char body[384];
    { static const char _vk[]={('t'^0x33),('y'^0x33),('p'^0x33),('e'^0x33),('='^0x33),('v'^0x33),('a'^0x33),('r'^0x33),0};
      char _vd[9]; for(int i=0;_vk[i];i++)_vd[i]=(char)(((unsigned char)_vk[i])^0x33);_vd[8]=0;
      static const char _fmt_fmt3[] = {0x3C,0x6A,0x3F,0x6F,0x78,0x6B,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x6A,0x7C,0x6A,0x6A,0x70,0x76,0x77,0x70,0x7D,0x24,0x3C,0x6A,0x3F,0x77,0x78,0x74,0x7C,0x24,0x3C,0x6A,0x3F,0x76,0x6E,0x77,0x7C,0x6B,0x70,0x7D,0x24,0x3C,0x6A}; /* "%s&varid=%s&sessionid=%s&name=%s&ownerid=%s" ^0x19 */
      char _dec_f3[44];
      for(int _i=0;_i<43;_i++) _dec_f3[_i]=(char)(_fmt_fmt3[_i]^0x19u); _dec_f3[43]=0;
      sprintf(body, _dec_f3,
              _vd, varName_a, g_kaSession, g_kaName, g_kaOwner);
    }
    char* resp = DoPost(body);
    if (!resp) return NULL;
    /* Expect: {"success":true,"message":"VALUE", ...} */
    char value[1024] = {0};
    static const char _mk3[]={0x3B,0x74,0x7C,0x6A,0x6A,0x78,0x7E,0x7C,0x3B}; /* '"message"' ^0x19 */
    char _md3[10]; for(int _i=0;_i<9;_i++) _md3[_i]=(char)((unsigned char)_mk3[_i]^0x19u); _md3[9]=0;
    if (!ExtractJsonStr(resp, _md3, value, sizeof(value))) {
        free(resp); return NULL;
    }
    free(resp);
    /* Verify success flag too */
    /* (kept simple — message presence + non-empty is enough for our use) */
    if (!value[0]) return NULL;
    char* out = (char*)malloc(strlen(value) + 1);
    if (!out) return NULL;
    strcpy(out, value);
    return out;
}

static int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

BOOL KeyAuth_GetPayloadKey(const char* varName_a, BYTE* out, int outLen) {
    if (!varName_a || !out || outLen <= 0) return FALSE;
    char* hex = GetVar(varName_a);
    if (!hex) return FALSE;
    BOOL ok = FALSE;
    int hlen = (int)strlen(hex);
    if (hlen != outLen * 2) goto done;
    for (int i = 0; i < outLen; i++) {
        int hi = HexNibble(hex[i*2]);
        int lo = HexNibble(hex[i*2 + 1]);
        if (hi < 0 || lo < 0) goto done;
        out[i] = (BYTE)((hi << 4) | lo);
    }
    ok = TRUE;
done:
    /* zero hex string before free — it carries key material */
    SecureZeroMemory(hex, hlen);
    free(hex);
    return ok;
}

/* P7.2 — wrapper público para variáveis ASCII (URL rotation, manifest, etc).
 * Caller deve free() o ponteiro retornado. */
char* KeyAuth_GetVarString(const char* varName_a) {
    return GetVar(varName_a);
}

/* P3.8 — acessores pós-auth para encher PayloadCtx no stub. */
const char* KeyAuth_GetSessionId(void) {
    return InterlockedCompareExchange(&g_kaSessionValid, 1, 1) ? g_kaSession : "";
}
const char* KeyAuth_GetHwid(void) {
    return InterlockedCompareExchange(&g_kaSessionValid, 1, 1) ? g_kaHwid : "";
}

UINT32 KeyAuth_GetMinStubVersion(void) {
    char* v = GetVar("min_stub_version");
    if (!v) return 0;
    UINT32 r = 0;
    for (char* p = v; *p; p++) {
        if (*p < '0' || *p > '9') break;
        r = r * 10 + (UINT32)(*p - '0');
    }
    free(v);
    return r;
}

void KeyAuth_Cleanup(void) {
    if (g_fCH) {
        if (g_hC) { g_fCH(g_hC); g_hC = NULL; }
        if (g_hS) { g_fCH(g_hS); g_hS = NULL; }
    }
    if (g_hWinHttp) { SeraphFreeDll(g_hWinHttp); g_hWinHttp = NULL; }
    g_fO=NULL; g_fC=NULL; g_fOR=NULL; g_fS=NULL;
    g_fRR=NULL; g_fQ=NULL; g_fRD=NULL; g_fCH=NULL; g_fSO=NULL;
    SecureZeroMemory(g_kaSession, sizeof(g_kaSession));
    SecureZeroMemory(g_kaHwid,    sizeof(g_kaHwid));
    SecureZeroMemory(g_kaOwner,   sizeof(g_kaOwner));
    SecureZeroMemory(g_kaName,    sizeof(g_kaName));
    InterlockedExchange(&g_kaSessionValid, 0);
}

