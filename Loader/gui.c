
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "gui.h"
#include "checks.h"
#include "keyauth.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "lazyhook.h"
#include "attach.h"
#include "Loader.h"
#include "antire.h"
#include "antire_handles.h"
#include "evasion_user.h"
#include "Overlay.h"
#include "esp_overlay.h"
#include "suicide.h"
#include "teleports.h"
#ifdef SERAPH_DMA_BUILD
#include "seraph_fuser.h"
#endif
#include "Resource.h"
#include "XorStr.h"
#include "debug.h"
#include "self_hash.h"
#include "payload_entry.h"
#include "payload_ctx.h"
#include "seraph_menu_trigger.h"
#include <stdio.h>
#include <wincrypt.h>  /* B-19: DPAPI CryptProtectData/CryptUnprotectData */
#include "xor_strings.h"
#include "syscalls.h"  /* SeraphSleep, SeraphCreateThread, SysNtUserGetAsyncKeyState */
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

static int g_HotkeyBaseId = 0;

static void InitHotkeyBaseId(void) {
    if (g_HotkeyBaseId == 0) {
        DWORD volSerial = 0;
        GetVolumeInformationW(DXOR_W(ENC_drive_root), NULL, 0, &volSerial, NULL, NULL, NULL, 0);
        g_HotkeyBaseId = 1000 + (volSerial % 5000);
    }
}

#define HK_MENU (g_HotkeyBaseId + 1)
#define HK_FLY (g_HotkeyBaseId + 2)
#define HK_GS (g_HotkeyBaseId + 4)
#define HK_SUICIDE (g_HotkeyBaseId + 5)
#define HK_AIMBOT_HEAD (g_HotkeyBaseId + 6)
#define HK_OPK (g_HotkeyBaseId + 7)

/* RegisterHotKey() rejects mouse VKs (returns ERROR_INVALID_PARAMETER for
 * VK_LBUTTON / RBUTTON / MBUTTON / XBUTTON1 / XBUTTON2).  The user can still
 * BIND a mouse button to Menu/Fly/GameSpeed via the menu UI — but the OS
 * never delivers a WM_HOTKEY for it, which is why mouse-bound toggles
 * silently failed in release.  We detect those here and the main message
 * loop polls them with GetAsyncKeyState() instead.                          */
#define IS_MOUSE_VK(vk) ((vk)==VK_LBUTTON||(vk)==VK_RBUTTON||(vk)==VK_MBUTTON||(vk)==VK_XBUTTON1||(vk)==VK_XBUTTON2)

/* ── Runtime string decryption (XOR key 0xA5) — encrypted arrays carry no plaintext ── */
static const wchar_t* sx_c(const unsigned short* e, int n) {
    static wchar_t p[4][256]; static int idx=0;
    wchar_t* d=p[idx]; idx=(idx+1)%4;
    for(int i=0;i<n&&i<255;i++) d[i]=(wchar_t)(e[i]^0xA5u);
    d[n<255?n:255]=0; return d;
}
/* "C:\Windows\System32\sihost.exe" */
static const unsigned short k_img[]={0xe6,0x9f,0xf9,0xf2,0xcc,0xcb,0xc1,0xca,0xd2,0xd6,0xf9,0xf6,0xdc,0xd6,0xd1,0xc0,0xc8,0x96,0x97,0xf9,0xd6,0xcc,0xcd,0xca,0xd6,0xd1,0x8b,0xc0,0xdd,0xc0};
/* "sihost.exe" */
static const unsigned short k_cmd[]={0xd6,0xcc,0xcd,0xca,0xd6,0xd1,0x8b,0xc0,0xdd,0xc0};
/* "Loading cheat..." */
static const unsigned short k_loading[]={0xE9,0xCA,0xC4,0xC1,0xCC,0xCB,0xC2,0x85,0xC6,0xCD,0xC0,0xC4,0xD1,0x8B,0x8B,0x8B};
/* "Driver Error" */
static const unsigned short k_driverr[]={0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xE0,0xD7,0xD7,0xCA,0xD7};
/* "Driver load failed" */
static const unsigned short k_driverrf[]={0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xC9,0xCA,0xC4,0xC1,0x85,0xC3,0xC4,0xCC,0xC9,0xC0,0xC1};
/* "Driver load failed. Run as Administrator." */
static const unsigned short k_driverrfl[]={0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xC9,0xCA,0xC4,0xC1,0x85,0xC3,0xC4,0xCC,0xC9,0xC0,0xC1,0x8B,0x85,0xF7,0xD0,0xCB,0x85,0xC4,0xD6,0x85,0xE4,0xC1,0xC8,0xCC,0xCB,0xCC,0xD6,0xD1,0xD7,0xC4,0xD1,0xCA,0xD7,0x8B};
/* "Destiny 2" */
static const unsigned short k_d2title[]={0xE1,0xC0,0xD6,0xD1,0xCC,0xCB,0xDC,0x85,0x97};

static BOOL g_authSuccess = FALSE;

/* ── Async auth state ────────────────────────────────────────────────────── */
typedef enum { AUTH_IDLE=0, AUTH_IN_PROGRESS=1, AUTH_SUCCESS=2, AUTH_FAILED=3 } AuthState;
static volatile LONG  g_authState  = AUTH_IDLE;
static wchar_t        g_authErrMsg[256] = {0};
static wchar_t        g_authUser[64]  = {0};
static wchar_t        g_authKey[128]  = {0};

/* ── Async BYOVD init state ──────────────────────────────────────────────── */
typedef enum { BYOVD_IDLE=0, BYOVD_IN_PROGRESS=1, BYOVD_SUCCESS=2, BYOVD_FAILED=3 } ByovdState;
static volatile LONG g_byovdState = BYOVD_IDLE;
static HANDLE g_byovdThreadHandle = NULL;
static DWORD  g_byovdStartTick    = 0;




static DWORD WINAPI ByovdInitThread(LPVOID param) {
    (void)param;
    BOOL ok = FALSE;
    WLF("ByovdInitThread: START");
    __try {
        WLF("ByovdInitThread: calling BYOVD init");
        ok = InitializeSeraphProduct(NULL);
        WLF(ok ? "product init OK" : "product init FAILED");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        char _eb[80];
        static const char _eb_fmt[] = {0xE7,0xDC,0xCA,0xD3,0xC1,0xEC,0xCB,0xCC,0xD1,0xF1,0xCD,0xD7,0xC0,0xC4,0xC1,0x9F,0x85,0xE0,0xFD,0xE6,0xE0,0xF5,0xF1,0xEC,0xEA,0xEB,0x85,0xC6,0xCA,0xC1,0xC0,0x98,0x95,0xDD,0x80,0x95,0x9D,0xC9,0xFD};
        char _eb_dec[40];
        for (int _i = 0; _i < 39; _i++) _eb_dec[_i] = (char)(_eb_fmt[_i] ^ 0xA5u);
        _eb_dec[39] = 0;
        wsprintfA(_eb, _eb_dec, (unsigned long)GetExceptionCode());
        WLF(_eb);
        ok = FALSE;
    }
    InterlockedExchange(&g_byovdState, ok ? BYOVD_SUCCESS : BYOVD_FAILED);
    WLF(ok ? "byovdState -> SUCCESS" : "byovdState -> FAILED");
    return 0;
}

typedef struct { wchar_t key[128]; } AuthThreadParam;

static DWORD WINAPI AuthThread(LPVOID param) {
    AuthThreadParam* p = (AuthThreadParam*)param;
    wchar_t errMsg[256] = {0};
    KEYAUTH_RESULT res = KeyAuthValidate(p->key, errMsg, 256);
    /* Copy key to g_authKey before free so SaveCreds has it on AUTH_SUCCESS */
    wcsncpy(g_authKey, p->key, 127); g_authKey[127] = 0;
    free(p);
    if (res == KEYAUTH_SUCCESS) {
        InterlockedExchange(&g_authState, AUTH_SUCCESS);
    } else {
        if (errMsg[0]) {
            wcsncpy(g_authErrMsg, errMsg, 255); g_authErrMsg[255] = 0;
        } else {
            /* XOR-decoded auth error strings — keep out of .rdata in release.
             * Key=0xA5. All strings are neutral UI text; XOR'd to prevent
             * YARA rules matching "License key expired" + "HWID mismatch". */
            switch(res) {
                /* "Network error" */
                case KEYAUTH_NETWORK_ERROR: {
                    static const USHORT _e0[]={0xEB^0xA5,0xC4^0xA5,0xD1^0xA5,0xD4^0xA5,0xCA^0xA5,0xD7^0xA5,0xC3^0xA5,0x85^0xA5,0xC4^0xA5,0xD7^0xA5,0xD7^0xA5,0xCA^0xA5,0xD7^0xA5};
                    WCHAR _d0[14]; for(int _i=0;_i<13;_i++) _d0[_i]=(WCHAR)(_e0[_i]^0xA5u); _d0[13]=0;
                    wcsncpy(g_authErrMsg,_d0,255); break; }
                /* "Invalid key" */
                case KEYAUTH_INVALID_KEY: {
                    static const USHORT _e1[]={0xEC^0xA5,0xCB^0xA5,0xD5^0xA5,0xC4^0xA5,0xCC^0xA5,0xC1^0xA5,0x85^0xA5,0xC3^0xA5,0xC4^0xA5,0xD8^0xA5};
                    WCHAR _d1[11]; for(int _i=0;_i<10;_i++) _d1[_i]=(WCHAR)(_e1[_i]^0xA5u); _d1[10]=0;
                    wcsncpy(g_authErrMsg,_d1,255); break; }
                /* "Key in use" */
                case KEYAUTH_KEY_ALREADY_USED: {
                    static const USHORT _e2[]={0xEE^0xA5,0xC4^0xA5,0xD8^0xA5,0x85^0xA5,0xCC^0xA5,0xCB^0xA5,0x85^0xA5,0xD0^0xA5,0xD6^0xA5,0xC4^0xA5};
                    WCHAR _d2[11]; for(int _i=0;_i<10;_i++) _d2[_i]=(WCHAR)(_e2[_i]^0xA5u); _d2[10]=0;
                    wcsncpy(g_authErrMsg,_d2,255); break; }
                /* "Key expired" */
                case KEYAUTH_KEY_EXPIRED: {
                    static const USHORT _e3[]={0xEE^0xA5,0xC4^0xA5,0xD8^0xA5,0x85^0xA5,0xC4^0xA5,0xD5^0xA5,0xD4^0xA5,0xCC^0xA5,0xD7^0xA5,0xC4^0xA5,0xC1^0xA5};
                    WCHAR _d3[12]; for(int _i=0;_i<11;_i++) _d3[_i]=(WCHAR)(_e3[_i]^0xA5u); _d3[11]=0;
                    wcsncpy(g_authErrMsg,_d3,255); break; }
                /* "Key banned" */
                case KEYAUTH_KEY_BANNED: {
                    static const USHORT _e4[]={0xEE^0xA5,0xC4^0xA5,0xD8^0xA5,0x85^0xA5,0xC2^0xA5,0xC0^0xA5,0xCB^0xA5,0xCB^0xA5,0xC4^0xA5,0xC1^0xA5};
                    WCHAR _d4[11]; for(int _i=0;_i<10;_i++) _d4[_i]=(WCHAR)(_e4[_i]^0xA5u); _d4[10]=0;
                    wcsncpy(g_authErrMsg,_d4,255); break; }
                /* "ID mismatch" */
                case KEYAUTH_HWID_MISMATCH: {
                    static const USHORT _e5[]={0xEC^0xA5,0xE1^0xA5,0x85^0xA5,0xCC^0xA5,0xCC^0xA5,0xD6^0xA5,0xCC^0xA5,0xCC^0xA5,0xCE^0xA5,0xC4^0xA5,0xD1^0xA5};
                    WCHAR _d5[12]; for(int _i=0;_i<11;_i++) _d5[_i]=(WCHAR)(_e5[_i]^0xA5u); _d5[11]=0;
                    wcsncpy(g_authErrMsg,_d5,255); break; }
                /* "No subscription" */
                case KEYAUTH_NO_SUBSCRIPTION: {
                    static const USHORT _e6[]={0xEB^0xA5,0xCA^0xA5,0x85^0xA5,0xD6^0xA5,0xD0^0xA5,0xC2^0xA5,0xD6^0xA5,0xD6^0xA5,0xC3^0xA5};
                    WCHAR _d6[10]; for(int _i=0;_i<9;_i++) _d6[_i]=(WCHAR)(_e6[_i]^0xA5u); _d6[9]=0;
                    wcsncpy(g_authErrMsg,_d6,255); break; }
                /* "Error" */
                default: {
                    static const USHORT _e7[]={0xE0^0xA5,0xD7^0xA5,0xD7^0xA5,0xCA^0xA5,0xD7^0xA5};
                    WCHAR _d7[6]; for(int _i=0;_i<5;_i++) _d7[_i]=(WCHAR)(_e7[_i]^0xA5u); _d7[5]=0;
                    wcsncpy(g_authErrMsg,_d7,255); break; }
            }
        }
        InterlockedExchange(&g_authState, AUTH_FAILED);
    }
    return 0;
}
HWND g_hMainWnd = NULL;
/* ── SpoofProcessName: make PEB show a legit process name ── */
static void SpoofProcessName(){
    typedef struct _US{USHORT Length;USHORT MaximumLength;PWSTR Buffer;}US;
    typedef struct _PP{BYTE b[16];PVOID r[10];US Image;US Cmd;}PP;
    typedef struct _PB{BYTE b[2];BYTE p[6];PVOID r[2];PVOID Ldr;PP* ProcessParameters;}PB;
    PB* peb=(PB*)__readgsqword(0x60);
    if(!peb||!peb->ProcessParameters) return;
    /* PEB spoof: sihost.exe is a neutral, low-profile Windows host process.
     * RuntimeBroker.exe is overused as a spoof target by known cheats — swap it. */
    static WCHAR s_img[40]={0};
    static WCHAR s_cmd[32]={0};
    static BOOL  s_dec=FALSE;
    if(!s_dec){
        s_dec=TRUE;
        for(int _i=0;_i<30;_i++) s_img[_i]=(WCHAR)(k_img[_i]^0xA5u); s_img[30]=0;
        for(int _i=0;_i<10;_i++) s_cmd[_i]=(WCHAR)(k_cmd[_i]^0xA5u); s_cmd[10]=0;
    }
    peb->ProcessParameters->Image.Buffer=s_img;
    peb->ProcessParameters->Image.Length=(USHORT)(30*2);
    peb->ProcessParameters->Image.MaximumLength=(USHORT)(31*2);
    peb->ProcessParameters->Cmd.Buffer=s_cmd;
    peb->ProcessParameters->Cmd.Length=(USHORT)(10*2);
    peb->ProcessParameters->Cmd.MaximumLength=(USHORT)(11*2);
}
static BOOL g_initialized=FALSE;
void CleanupTempDriver(){}

/* --- CREDENTIAL PERSISTENCE --- */
static void GetCredPath(WCHAR* out){
    /* P17: path encodado — L"\\Microsoft\\Devices\\a.dat" nunca aparece como literal */
    GetEnvironmentVariableW(L"APPDATA",out,MAX_PATH);
    WCHAR dir[MAX_PATH];
    wcscpy(dir,out);
    /* L"\\Microsoft\\Devices" decode */
    { static const unsigned short _pe[]={0xEB^0xA5,0xD4^0xA5,0xC8^0xA5,0xC7^0xA5,0xCA^0xA5,0xD6^0xA5,0xD1^0xA5,0xDA^0xA5,0x8A^0xA5,0x8A^0xA5,0xE1^0xA5,0xC0^0xA5,0xD2^0xA5,0xC4^0xA5,0xC7^0xA5,0xD1^0xA5,0xD6^0xA5};
      wchar_t _pd[18]; for(int i=0;i<17;i++)_pd[i]=(wchar_t)(_pe[i]^0xA5u);_pd[17]=0;
      wcscat(dir,_pd); }
    CreateDirectoryW(dir,NULL);
    wcscpy(out,dir);
    /* L"\\a.dat" decode */
    { static const unsigned short _fe[]={0xEB^0xA5,0xC4^0xA5,0x8B^0xA5,0xC7^0xA5,0xC4^0xA5,0xD1^0xA5};
      wchar_t _fd[7]; for(int i=0;i<6;i++)_fd[i]=(wchar_t)(_fe[i]^0xA5u);_fd[6]=0;
      wcscat(out,_fd); }
}
/* B-19: SaveCreds/LoadCreds agora usam Windows DPAPI.
 * CryptProtectData vincula os dados à conta Windows do usuário — um analista com
 * acesso ao disco mas sem a conta correta não consegue descriptografar.
 * Requer crypt32.lib (já adicionado ao b.bat). */
#pragma optimize("", off)
static void SaveCreds(const wchar_t* user, const wchar_t* key){
MUTATE_START
WCHAR path[MAX_PATH];
GetCredPath(path);
int uL=(int)(wcslen(user)+1)*2;
int kL=(int)(wcslen(key)+1)*2;
int total=uL+kL;
BYTE plain[512]={0};
DATA_BLOB bIn={0},bOut={0};
if(total>512) goto _sc_end;
for(size_t _i=0;_i<uL;_i++)plain[_i]=((BYTE*)user)[_i];
for(size_t _i=0;_i<kL;_i++)plain[uL+_i]=((BYTE*)key)[_i];
bIn.pbData=plain;
bIn.cbData=(DWORD)total;
if(!CryptProtectData(&bIn,NULL,NULL,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,&bOut)){
    SecureZeroMemory(plain,sizeof(plain));
    goto _sc_end;
}
SetFileAttributesW(path,FILE_ATTRIBUTE_NORMAL);
HANDLE hF=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
if(hF!=INVALID_HANDLE_VALUE){
    DWORD w; WriteFile(hF,bOut.pbData,bOut.cbData,&w,NULL); SysNtClose(hF);
}
LocalFree(bOut.pbData);
SecureZeroMemory(plain,sizeof(plain));
_sc_end:
MUTATE_END
}
#pragma optimize("", on)
static BOOL LoadCreds(wchar_t* user, wchar_t* key){
WCHAR path[MAX_PATH];
GetCredPath(path);
HANDLE hF=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
if(hF==INVALID_HANDLE_VALUE)return FALSE;
BYTE enc[1024]={0}; DWORD r;
ReadFile(hF,enc,sizeof(enc),&r,NULL); SysNtClose(hF);
if(r<16)return FALSE;
DATA_BLOB bIn={0},bOut={0};
bIn.pbData=enc;
bIn.cbData=r;
if(!CryptUnprotectData(&bIn,NULL,NULL,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,&bOut))return FALSE;
if(bOut.cbData<4||(int)bOut.cbData>512){
    LocalFree(bOut.pbData); return FALSE;
}
wchar_t* u=(wchar_t*)bOut.pbData;
int uL=(int)wcslen(u);
if(uL>=63||(int)((uL+1)*2)>=(int)bOut.cbData){
    LocalFree(bOut.pbData); return FALSE;
}
wcscpy(user,u);
wchar_t* k=(wchar_t*)(bOut.pbData+(uL+1)*2);
if(wcslen(k)>=127){
    LocalFree(bOut.pbData); return FALSE;
}
wcscpy(key,k);
LocalFree(bOut.pbData);
return TRUE;
}

/* --- LOGIN WNDPROC --- */
LRESULT CALLBACK LoginWndProc(HWND h,UINT m,WPARAM w,LPARAM l){
 switch(m){
 case WM_KEYDOWN:{
 if(GetKeyState(VK_CONTROL)&0x8000){
 if(w=='V'){
 /* Ctrl+V: paste do clipboard no campo com foco */
 if(OpenClipboard(h)){
 HANDLE hD=GetClipboardData(CF_UNICODETEXT);
 if(hD){
 wchar_t* txt=(wchar_t*)GlobalLock(hD);
 if(txt){
 for(int i=0;txt[i];i++){
 wchar_t c=txt[i];
 if(c>=32&&c<=126)Overlay_LoginChar(c);
 }
 GlobalUnlock(hD);
 }
 }
 CloseClipboard();
 }
 break;
 }
 if(w=='C'){
 /* Ctrl+C: copia o campo com foco para o clipboard */
 wchar_t user[64]={0},key[128]={0};
 Overlay_LoginGetCreds(user,64,key,128);
 wchar_t* src=(Overlay_LoginGetFocus()==0)?user:key;
 SIZE_T bytes=(wcslen(src)+1)*sizeof(wchar_t);
 HGLOBAL hG=GlobalAlloc(GMEM_MOVEABLE,bytes);
 if(hG){
 wchar_t* dst=(wchar_t*)GlobalLock(hG);
 if(dst){for(size_t _i=0;_i<bytes/sizeof(wchar_t);_i++)dst[_i]=((wchar_t*)src)[_i];GlobalUnlock(hG);}
 if(OpenClipboard(h)){EmptyClipboard();SetClipboardData(CF_UNICODETEXT,hG);CloseClipboard();}
 else GlobalFree(hG);
 }
 break;
 }
 }
 break;
 }
 case WM_CHAR:{
 wchar_t c=(wchar_t)w;
 /* Ignorar Ctrl+C e Ctrl+V aqui — ja tratados em WM_KEYDOWN */
 if(c==3||c==22)break;
 if(c=='\r')Overlay_LoginClick();
 else if(c=='\t')Overlay_LoginToggleFocus();
 else if(c=='\b')Overlay_LoginBackspace();
 else if(c>=32&&c<=126)Overlay_LoginChar(c);
 break;
 }
 case WM_LBUTTONDOWN:{
 int mx=LOWORD(l),my=HIWORD(l);
 Overlay_UpdateMouse(mx,my,TRUE);
 /* Close button (X): top-right, 18x22 area */
 if(mx>=274&&mx<=292&&my>=6&&my<=28){PostMessage(h,WM_CLOSE,0,0);break;}
 if(mx>=20&&mx<=280&&my>=214&&my<=254)Overlay_LoginSetFocus(0);
 else if(mx>=20&&mx<=280&&my>=290&&my<=330)Overlay_LoginSetFocus(1);
 else if(mx>=70&&mx<=230&&my>=358&&my<=390)Overlay_LoginClick();
 else{ReleaseCapture();SendMessage(h,WM_NCLBUTTONDOWN,HTCAPTION,0);}
 break;
 }
 case WM_LBUTTONUP:Overlay_UpdateMouse(LOWORD(l),HIWORD(l),FALSE);break;
 case WM_MOUSEMOVE:Overlay_UpdateMouse(LOWORD(l),HIWORD(l),!!(w&MK_LBUTTON));break;
 case WM_DESTROY:if(Overlay_IsRunning()) PostQuitMessage(0);break;
 }
 return DefWindowProc(h,m,w,l);
}

/* --- MAIN MENU WNDPROC --- */
LRESULT CALLBACK MainWndProc(HWND h,UINT m,WPARAM w,LPARAM l){
    InitHotkeyBaseId();
    switch(m){
    case WM_LBUTTONDOWN:{
        int mx=LOWORD(l),my=HIWORD(l);
        Overlay_UpdateMouse(mx,my,TRUE);
        /* Only drag from the header strip (top 50px). Clicks in the
           content area are handled by RenderMenu/CM() on the next frame. */
        if(my < 50){
            ReleaseCapture();
            SendMessage(h,WM_NCLBUTTONDOWN,HTCAPTION,0);
        } else {
            /* Ensure window has keyboard focus so WM_CHAR reaches text inputs
             * (TP name, config name, name changer, etc.). Without this, typed
             * characters go to whatever window currently has focus (e.g. D2). */
            SetFocus(h);
        }
        break;
    }
    /* Mouse-button rebind capture: any button except left (which is used to
     * click the menu UI itself) can be bound as a hotkey while we are in a
     * "waiting" state. FlyDir polls via GetAsyncKeyState so it accepts any
     * button; Menu/Fly/GS use RegisterHotKey which only accepts keyboard VKs
     * — we still attempt the bind and silently skip RegisterHotKey on failure. */
    case WM_MBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_XBUTTONDOWN:{
        int vk = 0;
        if(m==WM_MBUTTONDOWN) vk = VK_MBUTTON;
        else if(m==WM_RBUTTONDOWN) vk = VK_RBUTTON;
        else /* WM_XBUTTONDOWN */ vk = (HIWORD(w)==XBUTTON1)?VK_XBUTTON1:VK_XBUTTON2;
        if(Overlay_IsWaitingForFlyDirKey()){
            Overlay_SetFlyDirHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForFlyKey()){
            Overlay_SetFlyHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForTpKey()){
            Overlay_SetTpHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForAimbotKey()){
            Overlay_SetAimbotHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForAimbotTargetHeadKey()){
            Overlay_SetAimbotTargetHeadHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForSuicideKey()){
            UnregisterHotKey(h,HK_SUICIDE); Overlay_SetSuicideHotkey(vk);
            RegisterHotKey(h,HK_SUICIDE,MOD_NOREPEAT,(UINT)vk);
            return 0;
        }
        if(Overlay_IsWaitingForFuserKey()){
            Overlay_SetFuserHotkey(vk);
            return 0;
        }
        if(Overlay_IsWaitingForGsKey()){
            UnregisterHotKey(h,HK_GS); Overlay_SetGsHotkey(vk);
            RegisterHotKey(h,HK_GS,MOD_NOREPEAT,(UINT)vk);
            return 0;
        }
        if(Overlay_IsWaitingForOpkKey()){
            UnregisterHotKey(h,HK_OPK); Overlay_SetOpkHotkey(vk);
            RegisterHotKey(h,HK_OPK,MOD_NOREPEAT,(UINT)vk);
            return 0;
        }
        if(Overlay_IsWaitingForKey()){
            UnregisterHotKey(h,HK_MENU); Overlay_SetMenuHotkey(vk);
            RegisterHotKey(h,HK_MENU,MOD_NOREPEAT,(UINT)vk);
            return 0;
        }
    /* If no hotkey rebind is active, forward right-click to menu for TP deletion */
    if(m==WM_RBUTTONDOWN) {
        int mx=LOWORD(l),my=HIWORD(l);
        Overlay_UpdateRightMouse(mx,my,TRUE);
        return 0;
    }
    break;
}
case WM_RBUTTONUP:
Overlay_UpdateRightMouse(LOWORD(l),HIWORD(l),FALSE);
break;
case WM_LBUTTONUP:
Overlay_UpdateMouse(LOWORD(l),HIWORD(l),FALSE);
break;
case WM_MOUSEMOVE:
Overlay_UpdateMouse(LOWORD(l),HIWORD(l),!!(w&MK_LBUTTON));
break;
case WM_KEYDOWN:{
    if(Overlay_IsTextInputFocused()){
        if((int)w==VK_ESCAPE||(int)w==VK_RETURN){Overlay_TextInputDefocus();return 0;}
        if((int)w==VK_BACK){Overlay_TextInputBackspace();return 0;}
        return 0;
    }
    if(Overlay_IsNumInputFocused()){
        if((int)w==VK_ESCAPE||(int)w==VK_RETURN){Overlay_NumInputDefocus();return 0;}
        if((int)w==VK_BACK){Overlay_NumInputBackspace();return 0;}
        /* let WM_CHAR handle digit translation */
        return 0;
    }
    if(Overlay_IsWaitingForTpKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            Overlay_SetTpHotkey(vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            UnregisterHotKey(h,HK_MENU);
            Overlay_SetMenuHotkey(vk);
            if(vk>0) RegisterHotKey(h,HK_MENU,MOD_NOREPEAT,(UINT)vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForFlyKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            Overlay_SetFlyHotkey(vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForFlyDirKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            /* FlyDir hotkey is a HELD-FORWARD key polled by Fly_Tick via
             * GetAsyncKeyState — no RegisterHotKey, otherwise the OS would
             * swallow it from other windows. Just store the binding. */
            Overlay_SetFlyDirHotkey(vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForGsKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            UnregisterHotKey(h,HK_GS);
            Overlay_SetGsHotkey(vk);
            if(vk>0) RegisterHotKey(h,HK_GS,MOD_NOREPEAT,(UINT)vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForOpkKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            UnregisterHotKey(h,HK_OPK);
            Overlay_SetOpkHotkey(vk);
            if(vk>0) RegisterHotKey(h,HK_OPK,MOD_NOREPEAT,(UINT)vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForAimbotKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            Overlay_SetAimbotHotkey(vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForAimbotTargetHeadKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            Overlay_SetAimbotTargetHeadHotkey(vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForSuicideKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            UnregisterHotKey(h,HK_SUICIDE);
            Overlay_SetSuicideHotkey(vk);
            if(vk>0) RegisterHotKey(h,HK_SUICIDE,MOD_NOREPEAT,(UINT)vk);
        }
        return 0;
    }
    if(Overlay_IsWaitingForFuserKey()){
        int vk=(int)w;
        if(vk==VK_ESCAPE) vk=0;
        if(vk==0||(vk!=VK_SHIFT&&vk!=VK_CONTROL&&vk!=VK_MENU&&vk!=VK_LWIN&&vk!=VK_RWIN)){
            Overlay_SetFuserHotkey(vk);
        }
        return 0;
    }
    break;
}
case WM_CHAR:{
    if(Overlay_IsTextInputFocused()){
        wchar_t c=(wchar_t)w;
        if(c!=L'\b'&&c!=L'\r'&&c!=L'\t')Overlay_TextInputChar(c);
        return 0;
    }
    if(Overlay_IsNumInputFocused()){
        wchar_t c=(wchar_t)w;
        if(c>=L'0'&&c<=L'9'){Overlay_NumInputChar(c);}
        return 0;
    }
    break;
}
case WM_DESTROY:
PostQuitMessage(0);
break;
default:
return DefWindowProc(h,m,w,l);
}
return 0;
}

BOOL InitializeSeraphProduct(HWND hWnd){
    (void)hWnd;
    WLF("init product: start");
    if(g_initialized) {
        WLF("init product: already done");
        return TRUE;
    }
#ifdef SERAPH_DMA_BUILD
    WLF("init: calling DMA");
    if(!BYOVD_Init()){
        WLF("init: DMA failed");
        DEBUG_ERROR("DMA_Init failed");
#else
    WLF("init: calling driver");
    if(!BYOVD_Init()){
        WLF("init: driver failed");
        DEBUG_ERROR("BYOVD_Init failed");
#endif
        { static wchar_t _nbody[64];
          _snwprintf_s(_nbody,64,_TRUNCATE,L"Falha no step: [%d]",
              (int)g_byovdDiagStep);
          Overlay_AddNotification(sx_c(k_driverr,12), _nbody); }
        return FALSE;
    }
    g_initialized=TRUE;
#ifdef SERAPH_DMA_BUILD
    WLF("init: DMA ok");
#else
    WLF("init: driver ok");
    {char _en[16]={0};for(int _i=0;_i<10;_i++)_en[_i]=(char)((unsigned char)k_cmd[_i]^0xA5u);BYOVD_LOCK();BYOVD_SpoofProcessImageName(_en);BYOVD_UNLOCK();SecureZeroMemory(_en,sizeof(_en));}
#endif
    return TRUE;
}

/* ── PayloadInitDriver ──────────────────────────────────────────────────────
 * Thin wrapper around InitializeSeraphProduct so the new payload entry
 * (Loader/payload_entry.c::PayloadMain) can drive driver bring-up without
 * pulling in the full ShowMainGUI flow.  Idempotent — the underlying
 * InitializeSeraphProduct guards on g_initialized. */
BOOL PayloadInitDriver(void){
    return InitializeSeraphProduct(NULL);
}

/* ── PayloadRunMenu ─────────────────────────────────────────────────────────
 * Menu lifecycle: window class, hotkeys, render loop, cleanup.
 * Caller MUST guarantee:
 *   - InitializeSeraphProduct already returned TRUE (g_initialized set)
 *   - User authenticated
 * Returns when the user closes the menu.  Internally invokes the global
 * cleanup (Patch_RestoreAll, AntiRE_Stop, KeyAuth_Cleanup, BYOVD_Shutdown). */
void PayloadRunMenu(const PayloadCtx* ctx){
    (void)ctx;  /* reserved for future use: per-call logger override / identity */
    InitHotkeyBaseId();
    WriteLogFile("PayloadRunMenu: ENTER, criando menu window");
    /* Anti-RE: Exigir que a escrita de memoria do token de gatilho tenha ocorrido */
    if (!SeraphTrigger_ValidateAndConsume()) {
        WriteLogFile("PayloadRunMenu: ABORT & BAN (gatilho de memoria nao verificado)");
        SeraphTrigger_OnViolationBanAndExit();
        return;
    }
    /* Randomize class name and title — different LCG salt from login window */
    WCHAR szClsM[32],szTtlM[32];
    /* P9: seed neutro — 0x8D3B9E1C substituido para quebrar YARA */
    {ULONGLONG _s=(ULONGLONG)GetTickCount64()^(ULONGLONG)GetCurrentProcessId()^0x4A72B8E3ULL;
    for(int _i=0;_i<31;_i++){_s=_s*6364136223846793005ULL+1442695040888963407ULL;szClsM[_i]=L'a'+(WCHAR)((_s>>33)%26);_s=_s*6364136223846793005ULL+1442695040888963407ULL;szTtlM[_i]=L'a'+(WCHAR)((_s>>33)%26);}szClsM[31]=0;szTtlM[31]=0;}
    WriteLogFile("MENU: random names generated");
    WNDCLASSEXW wm={0};wm.cbSize=sizeof(wm);wm.lpfnWndProc=MainWndProc;wm.hInstance=GetModuleHandleW(NULL);wm.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);
    wm.lpszClassName=szClsM;RegisterClassExW(&wm);
    WriteLogFile("MENU: class registered");
    int mx2=(GetSystemMetrics(0)-800)/2,my2=(GetSystemMetrics(1)-680)/2;
    /* WS_EX_LAYERED is REQUIRED for stream-proof against legacy BitBlt capture.
       WDA_EXCLUDEFROMCAPTURE (0x11) contains the WDA_MONITOR bit (0x01) within
       its value — older capture APIs that only understand the MONITOR bit will
       render the window as BLACK in capture rather than excluding it.  With
       WS_EX_LAYERED the window is DWM-composited, so legacy BitBlt capture can't
       see its GDI surface at all; WGC uses the full affinity value and excludes.
       The "overlay signature" concern was overblown — legitimate apps use
       WS_EX_LAYERED constantly; its absence is what was leaking us. */
    HWND hMenu=CreateWindowExW(WS_EX_TOPMOST|WS_EX_LAYERED|WS_EX_TOOLWINDOW,szClsM,szTtlM,WS_POPUP|WS_VISIBLE,mx2,my2,800,680,NULL,NULL,wm.hInstance,NULL);
    if(hMenu){
        /* Full opacity via LWA_ALPHA=255 — window still renders normally to the
           user, but forced through DWM compositor (which is what makes it
           invisible to legacy capture). */
        SetLayeredWindowAttributes(hMenu, 0, 255, LWA_ALPHA);
    }
    {char _b[64]; wsprintfA(_b,"MENU: hMenu=%p",(void*)hMenu); WriteLogFile(_b);}
    if(hMenu){
        WriteLogFile("MENU: calling Overlay_Create");
        BOOL _oc = Overlay_Create(hMenu);
        {char _b[64]; wsprintfA(_b,"MENU: Overlay_Create=%d",_oc); WriteLogFile(_b);}
        if(_oc){
            WriteLogFile("MENU: Overlay_SetStreamProofWindow");
            Overlay_SetStreamProofWindow(hMenu,FALSE);
            WriteLogFile("MENU: Overlay_LoadConfigSettings");
            Overlay_LoadConfigSettings();
            /* Write-through: ensure config file always exists & reflects loaded state. */
            Overlay_SaveConfig();
            WriteLogFile("MENU: Overlay_SetMenuVisible");
            Overlay_SetMenuVisible(TRUE);
            SetForegroundWindow(hMenu);
            RegisterHotKey(hMenu,HK_MENU,MOD_NOREPEAT,(UINT)Overlay_GetMenuHotkey());

            { int _gsk=Overlay_GetGsHotkey(); if(_gsk>0) RegisterHotKey(hMenu,HK_GS,MOD_NOREPEAT,(UINT)_gsk); }
            { int _opkK=Overlay_GetOpkHotkey(); if(_opkK>0) RegisterHotKey(hMenu,HK_OPK,MOD_NOREPEAT,(UINT)_opkK); }
            { int _sk=Overlay_GetSuicideHotkey(); if(_sk>0) RegisterHotKey(hMenu,HK_SUICIDE,MOD_NOREPEAT,(UINT)_sk); }
            { int _thk=Overlay_GetAimbotTargetHeadHotkey(); if(_thk>0) RegisterHotKey(hMenu,HK_AIMBOT_HEAD,MOD_NOREPEAT,(UINT)_thk); }
            /* ESP overlay is started/stopped via the ESP tab toggle in the menu —
             * see Overlay_RebuildDevTab and the &g_espActive handler in gui_core.cpp.
             * Starting it here unconditionally would consume CPU + run W2S even when
             * the user hasn't enabled the feature.                                    */
            WriteLogFile("MENU: entering main loop");
            BOOL menuVis=TRUE;MSG mm;
            DWORD _lastTick=GetTickCount(); DWORD _frameCount=0; DWORD _lastPollMs = GetTickCount();
            /* ── Mouse-button hotkey polling state (edge-detect) ───────────────────────
             * Tracked separately for menu / fly-WASD / gamespeed.  Edge state is reset
             * whenever the bound VK changes (rebind), seeded with the CURRENT button
             * state so the click that performed the rebind is not interpreted as a
             * fresh press.  Keyboard hotkeys keep using the WM_HOTKEY path below.     */
            int _flyHkPrev=Overlay_GetFlyHotkey();   BOOL _flyDownPrev=(_flyHkPrev>0)?((SysNtUserGetAsyncKeyState(_flyHkPrev)&0x8000)!=0):FALSE;
            int _gsHkPrev =Overlay_GetGsHotkey();    BOOL _gsDownPrev =(_gsHkPrev >0&&IS_MOUSE_VK(_gsHkPrev ))?((SysNtUserGetAsyncKeyState(_gsHkPrev )&0x8000)!=0):FALSE;
            int _opkHkPrev=Overlay_GetOpkHotkey(); BOOL _opkDownPrev=(_opkHkPrev>0&&IS_MOUSE_VK(_opkHkPrev))?((SysNtUserGetAsyncKeyState(_opkHkPrev)&0x8000)!=0):FALSE;
            int _menuHkPrev=Overlay_GetMenuHotkey(); BOOL _menuDownPrev=(_menuHkPrev>0&&IS_MOUSE_VK(_menuHkPrev))?((SysNtUserGetAsyncKeyState(_menuHkPrev)&0x8000)!=0):FALSE;
            int _suicHkPrev=Overlay_GetSuicideHotkey(); BOOL _suicDownPrev=(_suicHkPrev>0&&IS_MOUSE_VK(_suicHkPrev))?((SysNtUserGetAsyncKeyState(_suicHkPrev)&0x8000)!=0):FALSE;
            int _thkPrev=Overlay_GetAimbotTargetHeadHotkey(); BOOL _thkDownPrev=(_thkPrev>0)?((SysNtUserGetAsyncKeyState(_thkPrev)&0x8000)!=0):FALSE;
#ifdef SERAPH_DMA_BUILD
            int _fuserHkPrev=Overlay_GetFuserHotkey(); BOOL _fuserDownPrev=(_fuserHkPrev>0)?((SysNtUserGetAsyncKeyState(_fuserHkPrev)&0x8000)!=0):FALSE;
#endif
            __try {
                while(Overlay_IsRunning()){
                    if(GetTickCount()-_lastTick>1000){_lastTick=GetTickCount();char _b[64];wsprintfA(_b,"MENU: alive, frames=%lu",_frameCount);WriteLogFile(_b);_frameCount=0;}_frameCount++;
                    if(PeekMessage(&mm,NULL,0,0,PM_REMOVE)){TranslateMessage(&mm);DispatchMessage(&mm);if(mm.message==WM_QUIT)break;if(mm.message==WM_HOTKEY){if((int)mm.wParam==HK_MENU){menuVis=!menuVis;Overlay_SetMenuVisible(menuVis);if(menuVis){ShowWindow(hMenu,SW_SHOW);SetForegroundWindow(hMenu);}else{ShowWindow(hMenu,SW_HIDE);HWND hGame=FindWindowW(NULL,sx_c(k_d2title,9));if(hGame)SetForegroundWindow(hGame);}}else if((int)mm.wParam==HK_FLY){Overlay_FlyToggle();}else if((int)mm.wParam==HK_GS){Overlay_GameSpeedToggle();}else if((int)mm.wParam==HK_OPK){Overlay_OpkToggle();}else if((int)mm.wParam==HK_SUICIDE){Suicide_Trigger();}else if((int)mm.wParam==HK_AIMBOT_HEAD){Overlay_AimbotTargetHeadToggle();}}}

                    DWORD _nowPoll = GetTickCount();
                    BOOL _lagged = (_nowPoll - _lastPollMs > 200);
                    _lastPollMs = _nowPoll;

                    BOOL _isFore = FALSE;
                    {
                        HWND _hFore = GetForegroundWindow();
                        HWND _hGame = FindWindowW(NULL, sx_c(k_d2title, 9));
                        _isFore = (_hFore == _hGame || _hFore == hMenu);
                    }

                    /* ── Mouse-button hotkey polling (edge detect on transition up→down) ──── */
                    {

                        /* Fly WASD */
                        int _fk=Overlay_GetFlyHotkey();
                        if (_fk > 0 && _fk <= 0xFE) {
                            if(_fk!=_flyHkPrev){_flyHkPrev=_fk;_flyDownPrev=((SysNtUserGetAsyncKeyState(_fk)&0x8000)!=0);}
                            if(!Overlay_IsWaitingForFlyKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_fk)&0x8000)!=0);
                                if(_d&&!_flyDownPrev&&!_lagged) Overlay_FlyToggle();
                                _flyDownPrev=_d;
                            }
                        } else {
                            _flyHkPrev = _fk;
                            _flyDownPrev = FALSE;
                        }
                        /* GameSpeed */
                        int _gk=Overlay_GetGsHotkey();
                        if (_gk > 0 && _gk <= 0xFE) {
                            if(_gk!=_gsHkPrev){_gsHkPrev=_gk;_gsDownPrev=(IS_MOUSE_VK(_gk))?((SysNtUserGetAsyncKeyState(_gk)&0x8000)!=0):FALSE;}
                            if(IS_MOUSE_VK(_gk)&&!Overlay_IsWaitingForGsKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_gk)&0x8000)!=0);
                                if(_d&&!_gsDownPrev&&!_lagged) Overlay_GameSpeedToggle();
                                _gsDownPrev=_d;
                            }
                        } else {
                            _gsHkPrev = _gk;
                            _gsDownPrev = FALSE;
                        }
                        /* Suicide (one-shot on edge up→down, mouse key only) */
                        int _sk=Overlay_GetSuicideHotkey();
                        if (_sk > 0 && _sk <= 0xFE) {
                            if(_sk!=_suicHkPrev){_suicHkPrev=_sk;_suicDownPrev=(IS_MOUSE_VK(_sk))?((SysNtUserGetAsyncKeyState(_sk)&0x8000)!=0):FALSE;}
                            if(IS_MOUSE_VK(_sk)&&!Overlay_IsWaitingForSuicideKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_sk)&0x8000)!=0);
                                if(_d&&!_suicDownPrev&&!_lagged) Suicide_Trigger();
                                _suicDownPrev=_d;
                            }
                        } else {
                            _suicHkPrev = _sk;
                            _suicDownPrev = FALSE;
                        }
                        /* Target Head/Body toggle hotkey (edge detect) */
                        int _thk=Overlay_GetAimbotTargetHeadHotkey();
                        if (_thk > 0 && _thk <= 0xFE) {
                            if(_thk!=_thkPrev){_thkPrev=_thk;_thkDownPrev=((SysNtUserGetAsyncKeyState(_thk)&0x8000)!=0);}
                            if(!Overlay_IsWaitingForAimbotTargetHeadKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_thk)&0x8000)!=0);
                                if(_d&&!_thkDownPrev&&!_lagged) Overlay_AimbotTargetHeadToggle();
                                _thkDownPrev=_d;
                            }
                        } else {
                            _thkPrev = _thk;
                            _thkDownPrev = FALSE;
                        }
#ifdef SERAPH_DMA_BUILD
                        /* Fuser mode toggle */
                        int _fhk=Overlay_GetFuserHotkey();
                        if (_fhk > 0 && _fhk <= 0xFE) {
                            if(_fhk!=_fuserHkPrev){_fuserHkPrev=_fhk;_fuserDownPrev=((SysNtUserGetAsyncKeyState(_fhk)&0x8000)!=0);}
                            if(!Overlay_IsWaitingForFuserKey()){
                                BOOL _fd=_isFore && ((SysNtUserGetAsyncKeyState(_fhk)&0x8000)!=0);
                                if(_fd&&!_fuserDownPrev&&!_lagged){
                                    BOOL _on = SeraphFuser_IsEnabled() ? FALSE : TRUE;
                                    SeraphFuser_SetEnabled(_on);
                                }
                                _fuserDownPrev=_fd;
                            }
                        } else {
                            _fuserHkPrev = _fhk;
                            _fuserDownPrev = FALSE;
                        }
#endif
                        /* OPK */
                        int _opkK=Overlay_GetOpkHotkey();
                        if (_opkK > 0 && _opkK <= 0xFE) {
                            if(_opkK!=_opkHkPrev){_opkHkPrev=_opkK;_opkDownPrev=(IS_MOUSE_VK(_opkK))?((SysNtUserGetAsyncKeyState(_opkK)&0x8000)!=0):FALSE;}
                            if(IS_MOUSE_VK(_opkK)&&!Overlay_IsWaitingForOpkKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_opkK)&0x8000)!=0);
                                if(_d&&!_opkDownPrev&&!_lagged) Overlay_OpkToggle();
                                _opkDownPrev=_d;
                            }
                        } else {
                            _opkHkPrev = _opkK;
                            _opkDownPrev = FALSE;
                        }
                        /* Menu */
                        int _mk=Overlay_GetMenuHotkey();
                        if (_mk > 0 && _mk <= 0xFE) {
                            if(_mk!=_menuHkPrev){_menuHkPrev=_mk;_menuDownPrev=(IS_MOUSE_VK(_mk))?((SysNtUserGetAsyncKeyState(_mk)&0x8000)!=0):FALSE;}
                            if(IS_MOUSE_VK(_mk)&&!Overlay_IsWaitingForKey()){
                                BOOL _d=_isFore && ((SysNtUserGetAsyncKeyState(_mk)&0x8000)!=0);
                                if(_d&&!_menuDownPrev&&!_lagged){
                                    menuVis=!menuVis;Overlay_SetMenuVisible(menuVis);
                                    if(menuVis){ShowWindow(hMenu,SW_SHOW);SetForegroundWindow(hMenu);}
                                    else{ShowWindow(hMenu,SW_HIDE);HWND _hG=FindWindowW(NULL,sx_c(k_d2title,9));if(_hG)SetForegroundWindow(_hG);}
                                }
                                _menuDownPrev=_d;
                            }
                        } else {
                            _menuHkPrev = _mk;
                            _menuDownPrev = FALSE;
                        }
                    }

                    /* ── TP slot hotkey polling (edge detect on transition up→down) ──── */
                    {
                        static int s_tpPrevKeys[TP_MAX_SLOTS] = {0};
                        static BOOL s_tpPrevDown[TP_MAX_SLOTS] = {0};
                        static BOOL s_tpInitialized = FALSE;
                        if (!s_tpInitialized) {
                            for (int i = 0; i < TP_MAX_SLOTS; i++) { s_tpPrevKeys[i] = 0; s_tpPrevDown[i] = FALSE; }
                            s_tpInitialized = TRUE;
                        }
                        for (int ti = 0; ti < TP_MAX_SLOTS; ti++) {
                            int hk = TP_GetHotkey(ti);
                            if (hk > 0 && hk <= 0xFE) {
                                if (hk != s_tpPrevKeys[ti]) {
                                    s_tpPrevKeys[ti] = hk;
                                    s_tpPrevDown[ti] = ((SysNtUserGetAsyncKeyState(hk) & 0x8000) != 0);
                                }
                                if (!Overlay_IsWaitingForTpKey()) {
                                    BOOL d = _isFore && ((SysNtUserGetAsyncKeyState(hk) & 0x8000) != 0);
                                    if (d && !s_tpPrevDown[ti] && !_lagged) TP_TeleportTo(ti);
                                    s_tpPrevDown[ti] = d;
                                } else {
                                    s_tpPrevDown[ti] = FALSE;
                                }
                            } else {
                                s_tpPrevKeys[ti] = hk;
                                s_tpPrevDown[ti] = FALSE;
                            }
                        }
                    }

                    /* ── Left / Right Arrow key TP navigation ────────────────────────── */
                    {
                        static BOOL s_leftArrowPrevDown = FALSE;
                        static BOOL s_rightArrowPrevDown = FALSE;

                        if (_isFore && (!menuVis || (!Overlay_IsTextInputFocused() && !Overlay_IsNumInputFocused() && !Overlay_IsWaitingForTpKey())))
                        {
                            BOOL leftDown = ((SysNtUserGetAsyncKeyState(VK_LEFT) & 0x8000) != 0);
                            BOOL rightDown = ((SysNtUserGetAsyncKeyState(VK_RIGHT) & 0x8000) != 0);

                            if (leftDown && !s_leftArrowPrevDown && !_lagged)
                            {
                                TP_TeleportPrev();
                            }
                            if (rightDown && !s_rightArrowPrevDown && !_lagged)
                            {
                                TP_TeleportNext();
                            }

                            s_leftArrowPrevDown = leftDown;
                            s_rightArrowPrevDown = rightDown;
                        }
                        else
                        {
                            s_leftArrowPrevDown = FALSE;
                            s_rightArrowPrevDown = FALSE;
                        }
                    }

                    /* P8: SelfHash periódico com jitter (5-15 minutos) */
                    {
                        static DWORD s_nextHashCheck = 0;
                        DWORD now = GetTickCount();
                        if (s_nextHashCheck == 0) {
                            /* Inicializa com jitter aleatório de 5-15 min */
                            DWORD jitter = 300000 + (DWORD)((now ^ (GetCurrentProcessId() << 8)) % 600000);
                            s_nextHashCheck = now + jitter;
                        } else if ((now - s_nextHashCheck) < 0x80000000UL && now >= s_nextHashCheck) {
                            if (!SelfHash_Verify()) {
                                /* SelfHash_Verify já bane e mata em RELEASE;
                                 * em DEBUG só retorna FALSE */
                                WriteLogFile("MENU: periodic SelfHash_Verify FAILED");
                            }
                            /* Próxima verificação: 5-15 min de jitter */
                            DWORD jitter2 = 300000 + (DWORD)((GetTickCount() ^ (GetCurrentProcessId() * 0x6D2B)) % 600000);
                            s_nextHashCheck = GetTickCount() + jitter2;
                        }
                    }

                    Overlay_RenderMenu();SeraphSleep(8);}

            } __except(EXCEPTION_EXECUTE_HANDLER) {
                char _eb[96]; wsprintfA(_eb,"MENU: EXCEPTION code=0x%08lX frames=%lu",(unsigned long)GetExceptionCode(),(unsigned long)_frameCount); WriteLogFile(_eb);
            }
            UnregisterHotKey(hMenu,HK_MENU);UnregisterHotKey(hMenu,HK_GS);UnregisterHotKey(hMenu,HK_SUICIDE);UnregisterHotKey(hMenu,HK_AIMBOT_HEAD);
            EspOverlay_Stop();
            Overlay_SaveConfig();Overlay_Destroy();DestroyWindow(hMenu);
        } /* if(_oc) */
    } /* if(hMenu) */
    /* Restore all patches and features before unloading driver */
    UINT64 cr3 = GetDestiny2CR3();
    if(cr3) {
        LazyHook_RemoveAll(cr3);
    }
    Attach_Invalidate();
    /* Always shutdown BYOVD on exit */
    AntiRE_Stop();
    AntiRE_Handles_Stop();
    /*KeyAuth_Cleanup();*/
    BYOVD_Shutdown();
    WriteLogFile("PayloadRunMenu: EXIT");
}

void ShowMainGUI(void){
    WriteLogFile("ShowMainGUI: starting");
    SeraphTrigger_InitSessionToken();
    SpoofProcessName();
    wchar_t savedUser[64]={0},savedKey[128]={0};
    BOOL hasSaved=LoadCreds(savedUser,savedKey);
    WriteLogFile("ShowMainGUI: hasSaved");

/* Randomize class name and window title per-run to avoid static string signatures */
WCHAR szCls1[32],szTtl1[32];
/* P9: seed neutro — 0x6C4F2A7B substituido */
{ULONGLONG _s=(ULONGLONG)GetTickCount64()^(ULONGLONG)GetCurrentProcessId()^0x2F8B1D6AULL;
for(int _i=0;_i<31;_i++){_s=_s*6364136223846793005ULL+1442695040888963407ULL;szCls1[_i]=L'a'+(WCHAR)((_s>>33)%26);_s=_s*6364136223846793005ULL+1442695040888963407ULL;szTtl1[_i]=L'a'+(WCHAR)((_s>>33)%26);}szCls1[31]=0;szTtl1[31]=0;}
WNDCLASSEXW w={0};w.cbSize=sizeof(w);w.lpfnWndProc=LoginWndProc;w.hInstance=GetModuleHandleW(NULL);w.hCursor=LoadCursorW(NULL,(LPCWSTR)IDC_ARROW);
w.lpszClassName=szCls1;
RegisterClassExW(&w);

int x=(GetSystemMetrics(0)-300)/2,y=(GetSystemMetrics(1)-420)/2;
/* WS_EX_NOACTIVATE removido — bloqueava foco de teclado, impedia digitar usuario/key.
 * Menu (que pode ficar visivel sobre o jogo) tambem nao usa essa flag. */
g_hMainWnd=CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW,szCls1,szTtl1,WS_POPUP|WS_VISIBLE,x,y,300,420,NULL,NULL,w.hInstance,NULL);
if(!g_hMainWnd){
#ifdef SERAPH_DMA_BUILD
    /* P1: "Seraph DMA" XOR decode — elimina literal Unicode em .rdata */
    { static const unsigned short _sdE[]={0xF6^0xA5,0xC0^0xA5,0xD7^0xA5,0xC4^0xA5,0xCC^0xA5,0x85^0xA5,0xE1^0xA5,0xD4^0xA5,0xC0^0xA5};
      wchar_t _sdW[10]; for(int i=0;i<9;i++)_sdW[i]=(wchar_t)(_sdE[i]^0xA5u);_sdW[9]=0;
      MessageBoxW(NULL, L"Falha ao criar janela de login.", _sdW, MB_ICONERROR | MB_OK); }
#endif
    return;
}
if(!Overlay_Create(g_hMainWnd)){
#ifdef SERAPH_DMA_BUILD
    { static const unsigned short _sdE[]={0xF6^0xA5,0xC0^0xA5,0xD7^0xA5,0xC4^0xA5,0xCC^0xA5,0x85^0xA5,0xE1^0xA5,0xD4^0xA5,0xC0^0xA5};
      wchar_t _sdW[10]; for(int i=0;i<9;i++)_sdW[i]=(wchar_t)(_sdE[i]^0xA5u);_sdW[9]=0;
      MessageBoxW(NULL,
        L"Falha ao iniciar interface (DirectWrite/D2D).\n"
        L"Atualize o Windows e drivers de video.",
        _sdW, MB_ICONERROR | MB_OK); }
#endif
    DestroyWindow(g_hMainWnd);
    g_hMainWnd = NULL;
    return;
}
    WriteLogFile("ShowMainGUI: setting foreground");
    SetForegroundWindow(g_hMainWnd);
    WriteLogFile("ShowMainGUI: setting focus");
    SetFocus(g_hMainWnd);

    if(hasSaved){
        WriteLogFile("ShowMainGUI: hasSaved, setting credentials");
        Overlay_LoginSetCreds(savedUser,savedKey);
        WriteLogFile("ShowMainGUI: hasSaved, credentials set");
    }
    MSG m;
    WriteLogFile("ShowMainGUI: entering message loop");
    while(Overlay_IsRunning()){
        static BOOL firstLoop = TRUE;
        if (firstLoop) {
            firstLoop = FALSE;
            WriteLogFile("ShowMainGUI: message loop running first frame");
        }
        if(PeekMessage(&m,NULL,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessage(&m);if(m.message==WM_QUIT)break;}

/* Checar resultado do auth thread */
LONG aState = InterlockedCompareExchange(&g_authState, AUTH_IDLE, AUTH_SUCCESS);
    if (aState == AUTH_SUCCESS) {
        WriteLogFile("Auth thread: SUCCESS");
        SaveCreds(g_authUser, g_authKey);
        g_authSuccess = TRUE;
        SeraphTrigger_WriteToken(); /* Efetua escrita de memoria do token de gatilho para liberar o menu */
        /* UeErasePEHeader(); -- Comentado temporariamente para testes de isolamento */
        InterlockedExchange(&g_byovdState, BYOVD_IN_PROGRESS);
        WriteLogFile("Auth Success: spawning ByovdInitThread...");
        HANDLE hBT = SeraphCreateThread(ByovdInitThread, NULL);
        if (hBT) {
            WriteLogFile("Auth Success: ByovdInitThread spawned successfully");
            SysNtDuplicateObject(SERAPH_CURRENT_PROCESS, hBT, SERAPH_CURRENT_PROCESS,
                            &g_byovdThreadHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
            g_byovdStartTick = GetTickCount();
            SysNtClose(hBT);
        } else {
            DWORD err = GetLastError();
            char errBuf[128];
            wsprintfA(errBuf, "Auth Success: CreateThread ByovdInitThread FAILED, GLE=%lu", err);
            WriteLogFile(errBuf);
            InterlockedExchange(&g_byovdState, BYOVD_FAILED);
            Overlay_Stop();
        }
        AntiRE_Start();  /* begin monitoring for RE tools */

    } else {
    aState = InterlockedCompareExchange(&g_authState, AUTH_IDLE, AUTH_FAILED);
    if (aState == AUTH_FAILED) {
        WriteLogFile("Auth thread: FAILED");
        static const unsigned short _w_Invalid_license_key[] = {0xEC,0xCB,0xD3,0xC4,0xC9,0xCC,0xC1,0x85,0xC9,0xCC,0xC6,0xC0,0xCB,0xD6,0xC0,0x85,0xCE,0xC0,0xDC};
        wchar_t _dec_ilk[20];
        for (int _i = 0; _i < 19; _i++) _dec_ilk[_i] = (wchar_t)(_w_Invalid_license_key[_i] ^ 0xA5u);
        _dec_ilk[19] = 0;
        Overlay_LoginShowErrorMsg(g_authErrMsg[0] ? g_authErrMsg : _dec_ilk);
    }
}

/* Enquanto autenticando, mostra login normal */
if(g_authState == AUTH_IN_PROGRESS){
    Overlay_RenderLogin();
    SeraphSleep(16);
    continue;
}

/* Enquanto driver carrega, mostra loading screen + timeout 60s */
if(g_byovdState == BYOVD_IN_PROGRESS){
    static wchar_t s_loadTxt[96];
    const char *_step = (const char*)0; (void)_step;
    /* Use the pre-encoded k_loading array — keeps "Loading..." out of .rdata */
    { static wchar_t _ld[20]={0}; static BOOL _ldd=FALSE;
      if(!_ldd){_ldd=TRUE;for(int _i=0;_i<16;_i++)_ld[_i]=(wchar_t)(k_loading[_i]^0xA5u);_ld[16]=0;}
      _snwprintf_s(s_loadTxt, 96, _TRUNCATE, L"%s [%d]", _ld, (int)g_byovdDiagStep); }
    Overlay_RenderLoading(s_loadTxt);
    if(g_byovdStartTick && (GetTickCount() - g_byovdStartTick) > 60000){
        g_authSuccess = FALSE;
        g_initialized = FALSE;
#ifdef SERAPH_DMA_BUILD
        BYOVD_Shutdown();
#else
        if(g_byovdThreadHandle){ TerminateThread(g_byovdThreadHandle,1); }
#endif
        if(g_byovdThreadHandle){ SysNtClose(g_byovdThreadHandle); g_byovdThreadHandle=NULL; }
        InterlockedExchange(&g_byovdState, BYOVD_FAILED);
        /* XOR-decoded timeout message — avoids 'MemProcFS' in .rdata
         * (key 0xA5; message is generic driver timeout text) */
        { static const USHORT _tmE[]={0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xD1,0xCC,0xC8,0xC0,0xCA,0xD0,0xD1,0x8B};
          wchar_t _tmW[16]; for(int _ti=0;_ti<15;_ti++)_tmW[_ti]=(wchar_t)(_tmE[_ti]^0xA5u);_tmW[15]=0;
          Overlay_LoginShowErrorMsg(_tmW); }
    }
    SeraphSleep(16);
    continue;
}
if(g_byovdState == BYOVD_SUCCESS){
    /* ── Pre-warm FIT during loading screen ─────────────────────────────
     * Kick off attach + feature-init thread now, BEFORE the menu window
     * is created. This way most/all expensive AOB scans + hook installs
     * complete while the user still sees the loading screen.
     *
     * SECURITY: this branch is only reached after auth succeeds (login
     * → AUTH_SUCCESS → BYOVD_IN_PROGRESS → BYOVD_SUCCESS). An unauth'd
     * caller can never reach here. Idempotent — safe across retries. */
    static BOOL s_fitKicked = FALSE;
    static DWORD s_fitWaitStart = 0;
    if(!s_fitKicked){
        s_fitKicked = TRUE;
        s_fitWaitStart = GetTickCount();
        WriteLogFile("Loading: pre-warming FIT");
        Overlay_StartFeatureInit();
    }
    /* Keep loading screen up briefly (~3.2s = ~40% of FIT total time) so the
     * heaviest scans get a head start; the rest of FIT continues in background
     * after the menu opens.  "cheat initialized" notif fires whenever FIT
     * actually completes (could be during loading OR after menu is up). */
    if(!Overlay_IsFeatureInitDone() && (GetTickCount() - s_fitWaitStart) < 3200){
        Overlay_RenderLoading(sx_c(k_loading,16));
        SeraphSleep(16);
        continue;
    }
    WriteLogFile(Overlay_IsFeatureInitDone() ? "Loading: FIT done early" : "Loading: handoff to background");
    Overlay_Stop();
    continue;
}
if(g_byovdState == BYOVD_FAILED){
    g_authSuccess = FALSE;
    InterlockedExchange(&g_byovdState, BYOVD_IDLE);
    { static wchar_t _emsg[128];
      static const unsigned short _w_Driver_error_step_pctddot_Run_as_Admindot[] = {0xE1,0xD7,0xCC,0xD3,0xC0,0xD7,0x85,0xC0,0xD7,0xD7,0xCA,0xD7,0x85,0xD6,0xD1,0xC0,0xD5,0x85,0x80,0xC1,0x8B,0x85,0xF7,0xD0,0xCB,0x85,0xC4,0xD6,0x85,0xE4,0xC1,0xC8,0xCC,0xCB,0x8B};
      wchar_t _dec_de[36];
      for (int _i = 0; _i < 35; _i++) _dec_de[_i] = (wchar_t)(_w_Driver_error_step_pctddot_Run_as_Admindot[_i] ^ 0xA5u);
      _dec_de[35] = 0;
      _snwprintf_s(_emsg,128,_TRUNCATE,_dec_de,
          (int)g_byovdDiagStep);
      Overlay_LoginShowErrorMsg(_emsg); }
}

if(Overlay_LoginWasClicked()){
   WriteLogFile("Overlay_LoginWasClicked triggered");
   wchar_t user[64]={0},key[128]={0};
   Overlay_LoginGetCreds(user,64,key,128);

if(!user[0]){
    static const unsigned short _w_Username_obrigatorio[] = {0xF0,0xD6,0xC0,0xD7,0xCB,0xC4,0xC8,0xC0,0x85,0xCA,0xC7,0xD7,0xCC,0xC2,0xC4,0xD1,0xCA,0xD7,0xCC,0xCA};
    wchar_t _dec_uo[21];
    for (int _i = 0; _i < 20; _i++) _dec_uo[_i] = (wchar_t)(_w_Username_obrigatorio[_i] ^ 0xA5u);
    _dec_uo[20] = 0;
    Overlay_LoginShowErrorMsg(_dec_uo);
} else if(!key[0]){
    static const unsigned short _w_Chave_de_licenca_obrigatoria[] = {0xE6,0xCD,0xC4,0xD3,0xC0,0x85,0xC1,0xC0,0x85,0xC9,0xCC,0xC6,0xC0,0xCB,0xC6,0xC4,0x85,0xCA,0xC7,0xD7,0xCC,0xC2,0xC4,0xD1,0xCA,0xD7,0xCC,0xC4};
    wchar_t _dec_klo[29];
    for (int _i = 0; _i < 28; _i++) _dec_klo[_i] = (wchar_t)(_w_Chave_de_licenca_obrigatoria[_i] ^ 0xA5u);
    _dec_klo[28] = 0;
    Overlay_LoginShowErrorMsg(_dec_klo);
} else if(g_authState == AUTH_IDLE) {
    AuthThreadParam* p = (AuthThreadParam*)malloc(sizeof(AuthThreadParam));
    if(p) {
        wcsncpy(g_authUser, user, 63); g_authUser[63] = 0;
        wcsncpy(g_kaUsername, user, 63); g_kaUsername[63] = 0;
        wcsncpy(p->key, key, 127); p->key[127] = 0;
        g_authErrMsg[0] = 0;
        InterlockedExchange(&g_authState, AUTH_IN_PROGRESS);
        HANDLE hAT = SeraphCreateThread(AuthThread, p);
        if(hAT) { SysNtClose(hAT); WriteLogFile("Auth: thread launched"); }
        else {
            DWORD _gle = GetLastError();
            char _gleBuf[80];
            wsprintfA(_gleBuf, "Auth: CreateThread GLE=%lu", _gle);
            WriteLogFile(_gleBuf);
            free(p);
            InterlockedExchange(&g_authState, AUTH_IDLE);
            /* "Internal error" XOR 0xA5 - 14 chars */
            static const unsigned short _w_Internal_error[] = {0xEC,0xCB,0xD1,0xC0,0xD7,0xCB,0xC4,0xC9,0x85,0xC0,0xD7,0xD7,0xCA,0xD7};
            wchar_t _dec_ei[15];
            for (int _i = 0; _i < 14; _i++) _dec_ei[_i] = (wchar_t)(_w_Internal_error[_i] ^ 0xA5u);
            _dec_ei[14] = 0;
            Overlay_LoginShowErrorMsg(_dec_ei);
        }
    } else {
        WriteLogFile("Auth: malloc failed");
    }
} else {
    WriteLogFile("Auth: click ignored (not IDLE)");
}
}

Overlay_RenderLogin();
SeraphSleep(10);
}
WriteLogFile("Exited overlay loop");
/* If BYOVD thread is still running (e.g. user closed window early), wait up to 30s */
if(g_byovdState == BYOVD_IN_PROGRESS){
    for(int _w=0; _w<300 && g_byovdState==BYOVD_IN_PROGRESS; _w++) SeraphSleep(100);
}
Overlay_Destroy();DestroyWindow(g_hMainWnd);

if(g_authSuccess && g_initialized){
    /* Backward-compat path: monolithic flow.  In the new architecture the
     * stub calls PayloadMain → PayloadRunMenu directly. */
    PayloadRunMenu(NULL);
}
}

