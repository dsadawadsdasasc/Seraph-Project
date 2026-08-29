/* stub_login.c — Login UI loop for Stub.exe.
 *
 * This is the ONLY surface area of the stub that interacts with the user.
 * After Stub_RunLoginPhase() returns TRUE, the stub proceeds to:
 *   - (Phase 3.3) Fetch AES + HMAC keys from KeyAuth via type=var
 *   - (Phase 3) Download manifest + payload.bin from GitHub
 *   - (Phase 4) Manual-map svc.dll
 *   - Call PayloadMain(ctx)
 *
 * For now (Phase 1) the result struct's aes_key/hmac_key/min_stub_version
 * fields stay zeroed; the caller falls back to LoadLibrary("svc.dll") on
 * a local plaintext file for the C1 checkpoint.
 *
 * IMPORTANT: this file is the new home of login machinery that previously
 * lived inside gui.c::ShowMainGUI.  In Phase 1 BOTH gui.c (legacy login)
 * and this file (new login) coexist — they don't conflict because all
 * helpers in this file are file-static.  Phase 2 deletes the gui.c login
 * portion and ShowMainGUI calls Stub_RunLoginPhase as the single source.
 */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "stub_login.h"
/* Bare includes — relies on the build adding /I "Loader" so the existing
 * shared headers resolve.  Both legacy b.bat and future build_stub.bat
 * pass that switch. */
#include "keyauth.h"
#include "Overlay.h"
#include "antire.h"
#include "ThemidaSDK.h"
#include "debug.h"

#include <windows.h>
#include <wincrypt.h>     /* DPAPI */
#include <stdio.h>
#include <wchar.h>
#include <string.h>

/* Pull WriteLogFile from gui.c (legacy sink in monolithic build).  When
 * Phase 2 splits the binaries, this becomes a no-op stub the stub_entry
 * provides directly. */
#ifndef WriteLogFile
extern void WriteLogFile(const char* msg);
#endif

/* ── XOR-decoded UI strings (key 0xA5) ────────────────────────────────────
 * Mirror of gui.c's k_* arrays; each TU has its own static copy. */
static const unsigned short s_k_img[]      = {0xE6,0x9F,0xF9,0xF2,0xCC,0xCB,0xC1,0xCA,0xD2,0xD6,0xF9,0xF6,0xDC,0xD6,0xD1,0xC0,0xC8,0x96,0x97,0xF9,0xF7,0xD0,0xCB,0xD1,0xCC,0xC8,0xC0,0xE7,0xD7,0xCA,0xCE,0xC0,0xD7,0x8B,0xC0,0xDD,0xC0};
static const unsigned short s_k_cmd[]      = {0xF7,0xD0,0xCB,0xD1,0xCC,0xC8,0xC0,0xE7,0xD7,0xCA,0xCE,0xC0,0xD7,0x8B,0xC0,0xDD,0xC0,0x85,0x88,0xE0,0xC8,0xC7,0xC0,0xC1,0xC1,0xCC,0xCB,0xC2};
static const unsigned short s_k_driverrfl[]= {0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xC9,0xCA,0xC4,0xC1,0x85,0xC3,0xC4,0xCC,0xC9,0xC0,0xC1,0x8B,0x85,0xF7,0xD0,0xCB,0x85,0xC4,0xD6,0x85,0xE4,0xC1,0xC8,0xCC,0xCB,0xCC,0xD6,0xD1,0xD7,0xC4,0xD1,0xCA,0xD7,0x8B};

/* Multi-buffer rotating decryptor (matches gui.c::sx_c semantics).
 * Returns a pointer valid until ~4 calls later. */
static const wchar_t* sxc(const unsigned short* enc, int n) {
    static wchar_t bufs[4][256];
    static int     idx = 0;
    wchar_t* d = bufs[idx]; idx = (idx + 1) % 4;
    for (int i = 0; i < n && i < 255; i++) d[i] = (wchar_t)(enc[i] ^ 0xA5u);
    d[n < 255 ? n : 255] = 0;
    return d;
}

/* ── Async auth state (file-static; used by AuthThread + Stub_RunLoginPhase) ── */
typedef enum { AUTH_IDLE = 0, AUTH_IN_PROGRESS = 1, AUTH_SUCCESS = 2, AUTH_FAILED = 3 } AuthState;
static volatile LONG s_authState = AUTH_IDLE;
static wchar_t       s_authErrMsg[256] = {0};
static wchar_t       s_authUser[64]    = {0};
static wchar_t       s_authKey[128]    = {0};

/* Static thread-arg buffer.  Auth is serialized by s_authState
 * (AUTH_IDLE → AUTH_IN_PROGRESS via InterlockedExchange before launching
 * the thread, AUTH_IN_PROGRESS → AUTH_SUCCESS/FAILED inside the thread),
 * so a single static instance is safe and keeps Stub.exe free of heap
 * allocations from the CRT for the auth path. */
typedef struct { wchar_t key[128]; } AuthThreadParam;
static AuthThreadParam s_authParam;

static DWORD WINAPI Stub_AuthThread(LPVOID param) {
    MUTATE_START
    AuthThreadParam* p = (AuthThreadParam*)param;
    wchar_t errMsg[256] = {0};
    KEYAUTH_RESULT res = KeyAuthValidate(p->key, errMsg, 256);
    SecureZeroMemory(p->key, sizeof(p->key));
    if (res == KEYAUTH_SUCCESS) {
        InterlockedExchange(&s_authState, AUTH_SUCCESS);
    } else {
        wcsncpy_s(s_authErrMsg, _countof(s_authErrMsg),
                  errMsg[0] ? errMsg : L"Invalid license key", _TRUNCATE);
        if (!s_authErrMsg[0]) {
            switch (res) {
                case KEYAUTH_NETWORK_ERROR:    wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"Network error"); break;
                case KEYAUTH_INVALID_KEY:      wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"Invalid license key"); break;
                case KEYAUTH_KEY_EXPIRED:      wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"License key expired"); break;
                case KEYAUTH_KEY_BANNED:       wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"Key banned"); break;
                case KEYAUTH_HWID_MISMATCH:    wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"HWID mismatch"); break;
                case KEYAUTH_NO_SUBSCRIPTION:  wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"No active subscription"); break;
                default:                       wcscpy_s(s_authErrMsg, _countof(s_authErrMsg), L"Server error"); break;
            }
        }
        InterlockedExchange(&s_authState, AUTH_FAILED);
    }
    MUTATE_END
    return 0;
}

/* ── PEB spoofing (RuntimeBroker.exe) ──────────────────────────────────────
 * Identical to gui.c::SpoofProcessName.  Runs once; subsequent calls are
 * no-ops because we cache the wide strings in static buffers. */
void Stub_SpoofProcessName(void) {
    typedef struct _US { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } US;
    typedef struct _PP { BYTE b[16]; PVOID r[10]; US Image; US Cmd; } PP;
    typedef struct _PB { BYTE b[2]; BYTE p[6]; PVOID r[2]; PVOID Ldr; PP* ProcessParameters; } PB;
    PB* peb = (PB*)__readgsqword(0x60);
    if (!peb || !peb->ProcessParameters) return;
    static WCHAR s_img[40] = {0};
    static WCHAR s_cmd[32] = {0};
    static BOOL  s_dec = FALSE;
    if (!s_dec) {
        s_dec = TRUE;
        for (int i = 0; i < 37; i++) s_img[i] = (WCHAR)(s_k_img[i] ^ 0xA5u); s_img[37] = 0;
        for (int i = 0; i < 28; i++) s_cmd[i] = (WCHAR)(s_k_cmd[i] ^ 0xA5u); s_cmd[28] = 0;
    }
    peb->ProcessParameters->Image.Buffer = s_img;
    peb->ProcessParameters->Image.Length = (USHORT)(37 * 2);
    peb->ProcessParameters->Image.MaximumLength = (USHORT)(38 * 2);
    peb->ProcessParameters->Cmd.Buffer = s_cmd;
    peb->ProcessParameters->Cmd.Length = (USHORT)(28 * 2);
    peb->ProcessParameters->Cmd.MaximumLength = (USHORT)(29 * 2);
}

/* LCG state for obfuscating text / window classes. */
static ULONG s_rndState = 123456789;

static HWND s_hLoginWnd = NULL;
static WCHAR s_szCls[32] = {0};
static HINSTANCE s_hInstance = NULL;

/* ── Utilities ───────────────────────────────────────────────────────────── */
/* ── DPAPI credential persistence ─────────────────────────────────────────
 * %APPDATA%\Microsoft\Devices\a.dat — DPAPI-protected so a disk forensic
 * dump without the user's Windows account cannot decrypt. */
static void GetCredPath(WCHAR* out) {
    GetEnvironmentVariableW(L"APPDATA", out, MAX_PATH);
    WCHAR dir[MAX_PATH];
    wcscpy_s(dir, MAX_PATH, out);
    wcscat_s(dir, MAX_PATH, L"\\Microsoft\\Devices");
    CreateDirectoryW(dir, NULL);
    wcscpy_s(out, MAX_PATH, dir);
    wcscat_s(out, MAX_PATH, L"\\a.dat");
}

static void SaveCreds(const wchar_t* user, const wchar_t* key) {
    MUTATE_START
    WCHAR path[MAX_PATH];
    GetCredPath(path);
    int uL = (int)(wcslen(user) + 1) * 2;
    int kL = (int)(wcslen(key)  + 1) * 2;
    int total = uL + kL;
    BYTE plain[512] = {0};
    DATA_BLOB bIn = {0}, bOut = {0};
    if (total > 512) goto _sc_end;
    for (int i = 0; i < uL; i++) plain[i] = ((BYTE*)user)[i];
    for (int i = 0; i < kL; i++) plain[uL + i] = ((BYTE*)key)[i];
    bIn.pbData = plain;
    bIn.cbData = (DWORD)total;
    if (!CryptProtectData(&bIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &bOut)) {
        SecureZeroMemory(plain, sizeof(plain));
        goto _sc_end;
    }
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(hF, bOut.pbData, bOut.cbData, &w, NULL);
        CloseHandle(hF);
    }
    LocalFree(bOut.pbData);
    SecureZeroMemory(plain, sizeof(plain));
_sc_end:
    MUTATE_END
}

BOOL Stub_LoadSavedCreds(WCHAR* user64, WCHAR* key128) {
    WCHAR path[MAX_PATH];
    GetCredPath(path);
    HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hF == INVALID_HANDLE_VALUE) return FALSE;
    BYTE enc[1024] = {0};
    DWORD r;
    ReadFile(hF, enc, sizeof(enc), &r, NULL);
    CloseHandle(hF);
    if (r < 16) return FALSE;
    DATA_BLOB bIn = {0}, bOut = {0};
    bIn.pbData = enc;
    bIn.cbData = r;
    if (!CryptUnprotectData(&bIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &bOut)) return FALSE;
    if (bOut.cbData < 4 || (int)bOut.cbData > 512) {
        LocalFree(bOut.pbData);
        return FALSE;
    }
    wchar_t* u = (wchar_t*)bOut.pbData;
    int uL = (int)wcslen(u);
    if (uL >= 63 || (int)((uL + 1) * 2) >= (int)bOut.cbData) {
        LocalFree(bOut.pbData);
        return FALSE;
    }
    wcscpy_s(user64, 64, u);
    wchar_t* k = (wchar_t*)(bOut.pbData + (uL + 1) * 2);
    if (wcslen(k) >= 127) {
        LocalFree(bOut.pbData);
        return FALSE;
    }
    wcscpy_s(key128, 128, k);
    LocalFree(bOut.pbData);
    return TRUE;
}

/* ── Login window proc (mirrors gui.c::LoginWndProc but file-static) ──── */
static LRESULT CALLBACK Stub_LoginWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_KEYDOWN: {
        if (GetKeyState(VK_CONTROL) & 0x8000) {
            if (w == 'V') {
                if (OpenClipboard(h)) {
                    HANDLE hD = GetClipboardData(CF_UNICODETEXT);
                    if (hD) {
                        wchar_t* txt = (wchar_t*)GlobalLock(hD);
                        if (txt) {
                            for (int i = 0; txt[i]; i++) {
                                wchar_t c = txt[i];
                                if (c >= 32 && c <= 126) Overlay_LoginChar(c);
                            }
                            GlobalUnlock(hD);
                        }
                    }
                    CloseClipboard();
                }
                break;
            }
            if (w == 'C') {
                wchar_t user[64] = {0}, key[128] = {0};
                Overlay_LoginGetCreds(user, 64, key, 128);
                wchar_t* src = (Overlay_LoginGetFocus() == 0) ? user : key;
                SIZE_T bytes = (wcslen(src) + 1) * sizeof(wchar_t);
                HGLOBAL hG = GlobalAlloc(GMEM_MOVEABLE, bytes);
                if (hG) {
                    wchar_t* dst = (wchar_t*)GlobalLock(hG);
                    if (dst) {
                        for (size_t i = 0; i < bytes / sizeof(wchar_t); i++)
                            dst[i] = ((wchar_t*)src)[i];
                        GlobalUnlock(hG);
                    }
                    if (OpenClipboard(h)) {
                        EmptyClipboard();
                        SetClipboardData(CF_UNICODETEXT, hG);
                        CloseClipboard();
                    } else {
                        GlobalFree(hG);
                    }
                }
                break;
            }
        }
        break;
    }
    case WM_CHAR: {
        wchar_t c = (wchar_t)w;
        if (c == 3 || c == 22) break;  /* Ctrl+C / Ctrl+V handled above */
        if (c == '\r')      Overlay_LoginClick();
        else if (c == '\t') Overlay_LoginToggleFocus();
        else if (c == '\b') Overlay_LoginBackspace();
        else if (c >= 32 && c <= 126) Overlay_LoginChar(c);
        break;
    }
    case WM_LBUTTONDOWN: {
        int mx = LOWORD(l), my = HIWORD(l);
        Overlay_UpdateMouse(mx, my, TRUE);
        if (mx >= 274 && mx <= 292 && my >= 6   && my <= 28)  { PostMessage(h, WM_CLOSE, 0, 0); break; }
        if (mx >= 20  && mx <= 280 && my >= 214 && my <= 254) Overlay_LoginSetFocus(0);
        else if (mx >= 20  && mx <= 280 && my >= 290 && my <= 330) Overlay_LoginSetFocus(1);
        else if (mx >= 70  && mx <= 230 && my >= 358 && my <= 390) Overlay_LoginClick();
        else { ReleaseCapture(); SendMessage(h, WM_NCLBUTTONDOWN, HTCAPTION, 0); }
        break;
    }
    case WM_LBUTTONUP:  Overlay_UpdateMouse(LOWORD(l), HIWORD(l), FALSE); break;
    case WM_MOUSEMOVE:  Overlay_UpdateMouse(LOWORD(l), HIWORD(l), !!(w & MK_LBUTTON)); break;
    case WM_DESTROY:
        if (Overlay_IsRunning()) PostQuitMessage(0);
        break;
    }
    return DefWindowProc(h, m, w, l);
}

/* ── Public entry: run login, return creds on success ──────────────────── */
BOOL Stub_RunLoginPhase(StubLoginResult* out) {
    MUTATE_START
    BOOL successOut = FALSE;
    if (!out) { goto done; }
    SecureZeroMemory(out, sizeof(*out));

    WriteLogFile("Stub_RunLoginPhase: ENTER");

    /* Reset shared auth state — calling this twice in one process should be
     * idempotent (e.g. user cancels, retries). */
    InterlockedExchange(&s_authState, AUTH_IDLE);
    s_authErrMsg[0] = 0;
    s_authUser[0]   = 0;
    s_authKey[0]    = 0;

    /* Restore prior session creds if available. */
    WCHAR savedUser[64] = {0}, savedKey[128] = {0};
    BOOL hasSaved = Stub_LoadSavedCreds(savedUser, savedKey);

    /* Randomize class & title — same LCG as gui.c so behaviour is identical. */
    WCHAR szCls[32], szTtl[32];
    {
        ULONGLONG s = (ULONGLONG)GetTickCount64() ^ (ULONGLONG)GetCurrentProcessId() ^ 0x6C4F2A7BULL;
        for (int i = 0; i < 31; i++) {
            s = s * 6364136223846793005ULL + 1442695040888963407ULL;
            szCls[i] = L'a' + (WCHAR)((s >> 33) % 26);
            s = s * 6364136223846793005ULL + 1442695040888963407ULL;
            szTtl[i] = L'a' + (WCHAR)((s >> 33) % 26);
        }
        szCls[31] = 0; szTtl[31] = 0;
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = Stub_LoginWndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.lpszClassName = szCls;
    RegisterClassExW(&wc);

    int x = (GetSystemMetrics(0) - 300) / 2;
    int y = (GetSystemMetrics(1) - 420) / 2;
    HWND hWnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                                szCls, szTtl, WS_POPUP | WS_VISIBLE,
                                x, y, 300, 420, NULL, NULL, wc.hInstance, NULL);
    if (!hWnd) {
        WriteLogFile("Stub_RunLoginPhase: CreateWindowExW failed");
        goto done;
    }
    if (!Overlay_Create(hWnd)) {
        DestroyWindow(hWnd);
        WriteLogFile("Stub_RunLoginPhase: Overlay_Create failed");
        goto done;
    }
    SetForegroundWindow(hWnd);
    SetFocus(hWnd);
    
    s_hLoginWnd = hWnd;
    wcsncpy_s(s_szCls, _countof(s_szCls), szCls, _TRUNCATE);
    s_hInstance = wc.hInstance;

    if (hasSaved) {
        Overlay_LoginSetCreds(savedUser, savedKey);
    }

    MSG   msg;

    /* AntiRE protects the download/decrypt window that follows.  Start now
     * so the login UI itself is also protected from RE tools attaching. */
    AntiRE_Start();

    while (Overlay_IsRunning()) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) break;
        }

        /* Auth thread → SUCCESS transition. */
        LONG st = InterlockedCompareExchange(&s_authState, AUTH_IDLE, AUTH_SUCCESS);
        if (st == AUTH_SUCCESS) {
            WriteLogFile("Stub_RunLoginPhase: AUTH_SUCCESS");
            SaveCreds(s_authUser, s_authKey);
            wcsncpy_s(out->username, _countof(out->username), s_authUser, _TRUNCATE);
            wcsncpy_s(out->key,      _countof(out->key),      s_authKey,  _TRUNCATE);
            /* P3.8 — propagar session_id + hwid para o payload via PayloadCtx. */
            {
                const char* sid = KeyAuth_GetSessionId();
                const char* hw  = KeyAuth_GetHwid();
                if (sid) { strncpy_s(out->session_id, sizeof(out->session_id), sid, _TRUNCATE); }
                if (hw)  { strncpy_s(out->hwid,       sizeof(out->hwid),       hw,  _TRUNCATE); }
            }
            /* P3.3 — fetch AES + HMAC keys + min_stub_version while the
             * KeyAuth session is still alive.  Failure here is fatal: we
             * cannot proceed to download a payload we can't decrypt. */
            Stub_SetLoadingText(L"Loading cheat... [Fetching Keys]");
            if (!KeyAuth_GetPayloadKey("aes_key",  out->aes_key,  32) ||
                !KeyAuth_GetPayloadKey("hmac_key", out->hmac_key, 32))
            {
                WriteLogFile("Stub_RunLoginPhase: KeyAuth_GetPayloadKey failed");
                Overlay_LoginShowErrorMsg(L"Failed to fetch payload keys");
                SecureZeroMemory(out->aes_key,  sizeof(out->aes_key));
                SecureZeroMemory(out->hmac_key, sizeof(out->hmac_key));
                Stub_SetLoadingText(L"Loading cheat... [Decryption/Init]");
                /* Keep loop running so the user sees the error and can retry. */
                continue;
            }
            Stub_SetLoadingText(L"Loading cheat... [Version Check]");
            out->min_stub_version = KeyAuth_GetMinStubVersion();
            successOut = TRUE;
            break;  /* exit loop — stub proceeds to download/decrypt/map */
        }

        /* Auth thread → FAILED transition. */
        st = InterlockedCompareExchange(&s_authState, AUTH_IDLE, AUTH_FAILED);
        if (st == AUTH_FAILED) {
            WriteLogFile("Stub_RunLoginPhase: AUTH_FAILED");
            Overlay_LoginShowErrorMsg(s_authErrMsg[0] ? s_authErrMsg : L"Invalid license key");
        }

        /* Render normal login while idle / in-progress. */
        if (s_authState == AUTH_IN_PROGRESS) {
            Overlay_RenderLogin();
            Sleep(16);
            continue;
        }

        /* Click handler — kick off auth thread. */
        if (Overlay_LoginWasClicked()) {
            WriteLogFile("Stub_RunLoginPhase: Login clicked");
            wchar_t user[64] = {0}, key[128] = {0};
            Overlay_LoginGetCreds(user, 64, key, 128);
            if (!user[0]) {
                Overlay_LoginShowErrorMsg(L"Username obrigatorio");
            } else if (!key[0]) {
                Overlay_LoginShowErrorMsg(L"Chave de licenca obrigatoria");
            } else if (s_authState == AUTH_IDLE) {
                wcsncpy_s(s_authUser, _countof(s_authUser), user, _TRUNCATE);
                wcsncpy_s(s_authKey,  _countof(s_authKey),  key,  _TRUNCATE);
                s_authErrMsg[0] = 0;
                /* Propagate GUI username to KeyAuth API client */
                wcsncpy_s(g_kaUsername, _countof(g_kaUsername), user, _TRUNCATE);
                /* s_authParam is static — interlock below ensures only one
                 * Stub_AuthThread is in flight at a time, so no race. */
                wcsncpy_s(s_authParam.key, _countof(s_authParam.key), key, _TRUNCATE);
                InterlockedExchange(&s_authState, AUTH_IN_PROGRESS);
                HANDLE hT = CreateThread(NULL, 0, Stub_AuthThread, &s_authParam, 0, NULL);
                if (!hT) {
                    SecureZeroMemory(&s_authParam, sizeof(s_authParam));
                    InterlockedExchange(&s_authState, AUTH_IDLE);
                    Overlay_LoginShowErrorMsg(L"CreateThread failed");
                } else {
                    CloseHandle(hT);
                }
            }
        }

        Overlay_RenderLogin();
        Sleep(10);
    }

    /* Window teardown (only if cancelled/failed). */
    if (!successOut) {
        Overlay_Destroy();
        DestroyWindow(hWnd);
        UnregisterClassW(szCls, wc.hInstance);
        s_hLoginWnd = NULL;
    }

done:
    WriteLogFile(successOut ? "Stub_RunLoginPhase: EXIT success" : "Stub_RunLoginPhase: EXIT cancelled");
    MUTATE_END
    return successOut;
}

extern HANDLE g_hCloseLoadingEvent;
extern HANDLE g_hLoadingDestroyedEvent;

static WCHAR s_loadingText[128] = L"Loading cheat... [Decryption/Init]";
static CRITICAL_SECTION s_loadingTextCs;
static BOOL s_loadingTextCsInit = FALSE;

void Stub_SetLoadingText(const wchar_t* text) {
    if (!s_loadingTextCsInit) {
        InitializeCriticalSection(&s_loadingTextCs);
        s_loadingTextCsInit = TRUE;
    }
    EnterCriticalSection(&s_loadingTextCs);
    wcsncpy_s(s_loadingText, _countof(s_loadingText), text, _TRUNCATE);
    LeaveCriticalSection(&s_loadingTextCs);
}

void Stub_RenderLoadingPhase(void) {
    if (!s_hLoginWnd) {
        /* Window doesn't exist — still signal destroyed so Stub_CloseLoadingScreen
         * doesn't hang forever in WaitForSingleObject(g_hLoadingDestroyedEvent, INFINITE) */
        if (g_hLoadingDestroyedEvent) SetEvent(g_hLoadingDestroyedEvent);
        return;
    }
    
    if (!s_loadingTextCsInit) {
        InitializeCriticalSection(&s_loadingTextCs);
        s_loadingTextCsInit = TRUE;
    }

    WriteLogFile("Stub_RenderLoadingPhase: entering loop");
    MSG msg;
    while (Overlay_IsRunning()) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) break;
        }
        
        if (g_hCloseLoadingEvent && WaitForSingleObject(g_hCloseLoadingEvent, 0) == WAIT_OBJECT_0) {
            WriteLogFile("Stub_RenderLoadingPhase: close event signaled");
            break;
        }
        
        WCHAR curText[128];
        EnterCriticalSection(&s_loadingTextCs);
        wcsncpy_s(curText, _countof(curText), s_loadingText, _TRUNCATE);
        LeaveCriticalSection(&s_loadingTextCs);

        Overlay_RenderLoading(curText);
        Sleep(16);
    }
    
    WriteLogFile("Stub_RenderLoadingPhase: destroying window");
    Overlay_Destroy();
    DestroyWindow(s_hLoginWnd);
    if (s_szCls[0] && s_hInstance) {
        UnregisterClassW(s_szCls, s_hInstance);
    }
    s_hLoginWnd = NULL;
    
    if (g_hLoadingDestroyedEvent) {
        SetEvent(g_hLoadingDestroyedEvent);
    }
}
