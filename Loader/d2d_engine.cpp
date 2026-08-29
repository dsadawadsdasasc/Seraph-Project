/* d2d_engine.cpp — Motor Direct2D puro compartilhado por Stub.exe e svc.dll.
 *
 * Extraído de gui_core.cpp (opção B do plano split_loader_plan.md):
 *   - Globals D2D: g_rT, g_d2F, g_dF, g_tF/sTF/mTF/bTF
 *   - Estado de janela e input básico: g_hW, g_r, g_mV, g_sR, g_mX/mY/lD
 *   - Estado de login: g_lU, g_lK, g_lFc, g_lCk, g_lEr*, g_lSt*
 *   - Stream-proof: g_streamProof, ApplyStreamProof, TickStreamProof
 *   - Config I/O básico: SaveConfig / LoadConfig (hotkeys + stream-proof toggle)
 *   - DrawEmblem, helpers DR/DT/DT_C/DTail, RenderNotifications
 *   - DX12Overlay: Create, Destroy, UpdateMouse, SetMenuVisible, IsMenuVisible,
 *                  GetActiveTab, SetActiveTab, Stop, IsRunning,
 *                  RenderLogin, RenderSystemCheck, RenderLoading
 *   - extern "C" wrappers: Overlay_Create/Destroy/Stop/IsRunning/UpdateMouse,
 *                          Overlay_Login*, Overlay_AddNotification*,
 *                          Overlay_SetStreamProofWindow, Overlay_LoadConfigSettings,
 *                          Overlay_SaveConfig, Overlay_SetSystemCheckResults,
 *                          Overlay_RenderLogin/RenderSystemCheck/RenderLoading
 *
 * NÃO incluído aqui: feature toggles, byovd.h, fly.h, gamespeed.h, etc.
 * Esses permanecem em gui_core.cpp (svc.dll only).
 *
 * Dependências externas esperadas pelo linker:
 *   - WriteLogFile (stub_log.c no Stub.exe; gui.c no payload)
 *   - g_checks.hypervisor / g_checks.secureboot (checks.c — no Stub.exe;
 *     declarados extern abaixo como g_cH / g_cS local via SetSystemCheckResults)
 *   - ConfigDecrypt (config_crypto.c — payload only; stub recebe SERAPH_BUILD_STUB)
 *   - g_hMainWnd (gui.c — payload; stub_entry.c — Stub.exe)
 */

#include <windows.h>
#include <shlobj.h>
#pragma comment(lib,"shell32.lib")
#include "d2d_engine.h"
#include "debug.h"
#include "XorStr.h"
#include <vector>
#include <string>
#include <map>
#include <dwrite.h>
#include <d2d1.h>
#include <cmath>
#pragma comment(lib,"d2d1.lib")
#pragma comment(lib,"dwrite.lib")

/* config_crypto.h só existe no payload.  No stub não há cfg AES legado. */
#ifndef SERAPH_BUILD_STUB
#include "config_crypto.h"
#endif

/* g_hMainWnd — definido em gui.c (payload) ou stub_entry.c (stub) */
extern "C" HWND g_hMainWnd;


/* ── Runtime XOR string decryption (chave 0xA5) ───────────────────────────── */
static const wchar_t* SX(const unsigned short* e, int n) {
    static wchar_t p[8][256]; static int idx=0;
    wchar_t* d=p[idx]; idx=(idx+1)%8;
    for(int i=0;i<n&&i<255;i++) d[i]=(wchar_t)(e[i]^0xA5u);
    d[n<255?n:255]=0; return d;
}
/* "seraph.gg" */
static const unsigned short k_seraphgg[]  ={0xD6,0xC0,0xD7,0xC4,0xD5,0xCD,0x8B,0xC2,0xC2};
/* "KeyAuth Authentication - Status: Active" */
static const unsigned short k_keyauth[]   ={0xEE,0xC0,0xDC,0xE4,0xD0,0xD1,0xCD,0x85,0xE4,0xD0,0xD1,0xCD,0xC0,0xCB,0xD1,0xCC,0xC6,0xC4,0xD1,0xCC,0xCA,0xCB,0x85,0x88,0x85,0xF6,0xD1,0xC4,0xD1,0xD0,0xD6,0x9F,0x85,0xE4,0xC6,0xD1,0xCC,0xD3,0xC0};
/* "Seraph" */
static const unsigned short k_seraph_hdr[]={0xF6,0xC0,0xD7,0xC4,0xD5,0xCD};
/* "SERAPH" (title, uppercase) */
static const unsigned short k_seraph_uc[] ={0xF6,0xE0,0xF7,0xE4,0xF5,0xED};

/* ── D2D/DWrite resource globals (linkagem externa: usados por gui_core.cpp) ── */
IDWriteFactory*          g_dF  = NULL;
IDWriteTextFormat*       g_tF  = NULL;  /* 18pt bold */
IDWriteTextFormat*       g_sTF = NULL;  /* 12pt bold */
IDWriteTextFormat*       g_mTF = NULL;  /* 14pt bold */
IDWriteTextFormat*       g_bTF = NULL;  /* 9pt regular */
ID2D1Factory*            g_d2F = NULL;
ID2D1HwndRenderTarget*   g_rT  = NULL;
HWND  g_hW  = NULL;
bool  g_r   = true;    /* rendering active flag */
bool  g_mV  = false;   /* menu visible */
RECT  g_sR  = {0,0,0,0};
ID2D1SolidColorBrush* g_scratchBr = NULL;

/* ── Mouse / click state (also used by gui_core.cpp via extern) ─────────────── */
int  g_mX = 0, g_mY = 0;
bool g_lD  = false;
bool g_rD  = false;

/* ── Login state ─────────────────────────────────────────────────────────────── */
static wchar_t g_lU[21]   = {0};   /* username field */
static wchar_t g_lK[128]  = {0};   /* license key field */
static int     g_lFc       = 0;    /* focus: 0=user, 1=key */
static bool    g_lCk       = false; /* login button clicked flag */
static bool    g_lEr       = false;
static float   g_lErT      = 0;
static wchar_t g_lErMsg[64]= L"Invalid credentials";
static bool    g_lSt       = false;
static float   g_lStT      = 0;
static wchar_t g_lStMsg[64]= L"";

/* ── System-check results (set via SetSystemCheckResults) ───────────────────── */
static bool g_cT = false;  /* trusted (unused by login path) */
static bool g_cS = false;  /* secure boot detected */
static bool g_cH = false;  /* HVCI detected */

/* ── Stream-proof (g_streamProof tem linkagem externa: lido por gui_core.cpp) ── */
bool g_streamProof     = true;
static bool g_streamProofPrev = false;
static HWND g_streamProofHwnd    = NULL;
static HWND g_espStreamProofHwnd = NULL;

/* ── Active tab (shared with gui_core.cpp via extern) ───────────────────────── */
int g_aT = 1;

/* ── Toast Notification System ──────────────────────────────────────────────── */
struct Notif {
    wchar_t hdr[80];
    wchar_t bdy[160];
    float   elapsed;
    float   yAnim;
    float   alpha;
    float   duration;
};
static const float NOTIF_W        = 260.f;
static const float NOTIF_H        = 70.f;
static const float NOTIF_PAD      = 8.f;
static const float NOTIF_X        = 14.f;
static const float NOTIF_TOP      = 62.f;
static const float NOTIF_DUR      = 2.5f;
static const float NOTIF_FADE     = 0.25f;
static const float NOTIF_HOTKEY_DUR = 1.5f;
static std::vector<Notif>  g_notifs;
static DWORD               g_notifLastTick = 0;

/* ── Hotkey state (lido por gui_core.cpp via extern + por gui.c) ─────────────── */
int g_menuHotkey    = VK_INSERT;
int g_flyHotkey     = 0;
int g_flyDirHotkey  = 0;
int g_gsHotkey      = 0;
int g_opkHotkey     = 0;
int g_aimbotHotkey  = VK_RBUTTON;
int g_aimbotTargetHeadHotkey = 0;
int g_suicideHotkey = 0;
int g_fuserHotkey   = 0;
/* "waiting for key" flags — set/read by gui_core.cpp input handler */
bool g_waitingForKey       = false;
bool g_waitingForFlyKey    = false;
bool g_waitingForFlyDirKey = false;
bool g_waitingForGsKey     = false;
bool g_waitingForAimbotKey    = false;
bool g_waitingForSuicideKey   = false;
bool g_waitingForAimbotTargetHeadKey = false;
bool g_waitingForFuserKey  = false;

/* ── Config I/O ──────────────────────────────────────────────────────────────── */
static void ApplyStreamProof(HWND hWnd, const wchar_t* tag);  /* fwd decl */

static void GetConfigPath(WCHAR* out) {
    out[0] = 0;
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, out))) {
        if (!GetEnvironmentVariableW(L"APPDATA", out, MAX_PATH) || !out[0])
            wcscpy(out, L".");
    }
    wcscat(out, L"\\Microsoft\\Devices");
    SHCreateDirectoryExW(NULL, out, NULL);
    wcscat(out, L"\\cfg.dat");
}

#define CFG_XOR_BYTE(i) ((BYTE)(0xC7 ^ ((i) & 0x1F)))

static void SaveConfig() {
    WCHAR path[MAX_PATH]; GetConfigPath(path);
    BYTE buf[64] = {0};
    buf[0] = (BYTE)(g_streamProof ? 1 : 0);
    buf[1] = (BYTE)(g_menuHotkey  & 0xFF);
    buf[2] = (BYTE)((g_menuHotkey >> 8) & 0xFF);
    buf[3] = (BYTE)(g_flyHotkey   & 0xFF);
    buf[4] = (BYTE)((g_flyHotkey  >> 8) & 0xFF);
    buf[5] = (BYTE)(g_flyDirHotkey  & 0xFF);
    buf[6] = (BYTE)((g_flyDirHotkey >> 8) & 0xFF);
    buf[7] = (BYTE)(g_gsHotkey   & 0xFF);
    buf[8] = (BYTE)((g_gsHotkey  >> 8) & 0xFF);
    /* P5: persist extra hotkeys (bytes 9-16) */
    buf[9]  = (BYTE)(g_aimbotHotkey           & 0xFF);
    buf[10] = (BYTE)((g_aimbotHotkey          >> 8) & 0xFF);
    buf[11] = (BYTE)(g_suicideHotkey          & 0xFF);
    buf[12] = (BYTE)((g_suicideHotkey         >> 8) & 0xFF);
    buf[13] = (BYTE)(g_aimbotTargetHeadHotkey & 0xFF);
    buf[14] = (BYTE)((g_aimbotTargetHeadHotkey>> 8) & 0xFF);
    buf[15] = (BYTE)(g_fuserHotkey            & 0xFF);
    buf[16] = (BYTE)((g_fuserHotkey           >> 8) & 0xFF);
    buf[17] = (BYTE)(g_opkHotkey              & 0xFF);
    buf[18] = (BYTE)((g_opkHotkey             >> 8) & 0xFF);
    for (int i = 0; i < 64; i++) buf[i] ^= CFG_XOR_BYTE(i);
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hF == INVALID_HANDLE_VALUE) {
        DEBUG_ERROR("SaveConfig: CreateFileW failed err=%lu", GetLastError());
        return;
    }
    DWORD w = 0;
    if (!WriteFile(hF, buf, 64, &w, NULL) || w != 64)
        DEBUG_ERROR("SaveConfig: WriteFile failed err=%lu w=%lu", GetLastError(), w);
    CloseHandle(hF);
}

void LoadConfig() {
    WCHAR path[MAX_PATH]; GetConfigPath(path);
    HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hF == INVALID_HANDLE_VALUE) return;
    BYTE raw[128] = {0};
    DWORD r = 0;
    ReadFile(hF, raw, sizeof(raw), &r, NULL);
    CloseHandle(hF);
    if (r < 1) return;
    BYTE buf[64] = {0};
#ifndef SERAPH_BUILD_STUB
    if (r > 64) {
        DWORD bufSize = sizeof(buf);
        if (!ConfigDecrypt(raw, r, buf, &bufSize)) {
            DEBUG_ERROR("LoadConfig: legacy AES decrypt failed; using defaults");
            return;
        }
    } else
#endif
    {
        if (r > sizeof(buf)) r = sizeof(buf);
        for (DWORD i = 0; i < r; i++) buf[i] = raw[i] ^ CFG_XOR_BYTE(i);
    }
    g_streamProof     = (buf[0] != 0);
    g_streamProofPrev = g_streamProof;
    if (r >= 3)  { int hk=(int)buf[1]|(((int)buf[2])<<8); if(hk>=0x08&&hk<=0xFE) g_menuHotkey=hk; }
    if (r >= 5)  { int hk=(int)buf[3]|(((int)buf[4])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_flyHotkey=hk; }
    if (r >= 7)  { int hk=(int)buf[5]|(((int)buf[6])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_flyDirHotkey=hk; }
    if (r >= 9)  { int hk=(int)buf[7]|(((int)buf[8])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_gsHotkey=hk; }
    /* P5: restore extra hotkeys */
    if (r >= 11) { int hk=(int)buf[9] |(((int)buf[10])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_aimbotHotkey=hk; }
    if (r >= 13) { int hk=(int)buf[11]|(((int)buf[12])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_suicideHotkey=hk; }
    if (r >= 15) { int hk=(int)buf[13]|(((int)buf[14])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_aimbotTargetHeadHotkey=hk; }
    if (r >= 17) { int hk=(int)buf[15]|(((int)buf[16])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_fuserHotkey=hk; }
    if (r >= 19) { int hk=(int)buf[17]|(((int)buf[18])<<8); if(hk==0||(hk>=0x01&&hk<=0xFE)) g_opkHotkey=hk; }
    if (g_streamProofHwnd)    ApplyStreamProof(g_streamProofHwnd,    L"menu");
    if (g_espStreamProofHwnd) ApplyStreamProof(g_espStreamProofHwnd, L"esp");
}

/* P6.4: WDA_EXCLUDEFROMCAPTURE e WDA_MONITOR são ativamente monitorados pelo BattlEye
 * via ObRegisterCallbacks em NtUserSetWindowDisplayAffinity. WS_EX_LAYERED
 * (aplicado na criação da janela em gui.c) já derrota captura BitBlt legada
 * via composição DWM. Stream-proof é um NO-OP no nível de API —
 * a janela layered é inerentemente invisível para captura de tela. */
static void ApplyStreamProof(HWND hWnd, const wchar_t* tag) {
    (void)hWnd;
    (void)tag;
    /* Intentionally empty — WS_EX_LAYERED covers capture protection. */
}

/* Called by DX12Overlay::RenderMenu every frame (impl in gui_core.cpp) */
void D2DEngine_TickStreamProof() {
    if (g_streamProof != g_streamProofPrev) {
        g_streamProofPrev = g_streamProof;
        ApplyStreamProof(g_streamProofHwnd,    L"menu");
        ApplyStreamProof(g_espStreamProofHwnd, L"esp");
        SaveConfig();
    }
}

/* ── D2D drawing helpers ─────────────────────────────────────────────────────── */
void DR(float x1,float y1,float x2,float y2,float r,float g,float b,float a){
    ID2D1SolidColorBrush*br=NULL;
    if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(r,g,b,a),&br))){
        g_rT->FillRectangle(D2D1::RectF(x1,y1,x2,y2),br);
        br->Release();
    }
}
void DT(const wchar_t*t,float x,float y,float r,float g,float b,float a,IDWriteTextFormat*fmt=NULL){
    if(!g_rT||(!fmt&&!g_mTF))return;
    IDWriteTextFormat*f=fmt?fmt:g_mTF;
    ID2D1SolidColorBrush*br=NULL;
    if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(r,g,b,a),&br))){
        D2D1_RECT_F rc={x,y,(float)g_sR.right,y+30};
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rc,br);
        br->Release();
    }
}
void DT_C(const wchar_t*t,float x1,float y1,float x2,float y2,float r,float g,float b,float a,IDWriteTextFormat*fmt=NULL){
    if(!g_rT||(!fmt&&!g_tF))return;
    IDWriteTextFormat*f=fmt?fmt:g_tF;
    ID2D1SolidColorBrush*br=NULL;
    if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(r,g,b,a),&br))){
        D2D1_RECT_F rc={x1,y1,x2,y2};
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        f->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rc,br);
        /* Reset to defaults — não query do estado anterior pq DWrite não tem
         * "stack" e o callsite original setava valores fake. Sem este reset,
         * DT() seguinte renderiza centralizado em vez de leading/near. */
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        f->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        br->Release();
    }
}
/* Right-clipped tail: draws text right-aligned clipped to [x1..x2] */
void DTail(const wchar_t*t,float x1,float x2,float y,float r,float gv,float b,float a,IDWriteTextFormat*fmt=NULL){
    if(!g_rT||(!fmt&&!g_mTF))return;
    IDWriteTextFormat*f=fmt?fmt:g_mTF;
    ID2D1SolidColorBrush*br=NULL;
    if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(r,gv,b,a),&br))){
        D2D1_RECT_F rc={x1,y,x2,y+30};
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rc,br);
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        br->Release();
    }
}

void DrawEmblem(ID2D1SolidColorBrush* /*unused*/,float cy=70.0f){
if(!g_rT||!g_d2F)return;
float cx=(float)g_sR.right*0.5f;
float s=0.45f;
D2D1_POINT_2F outer[6]={
    {cx+  0*s, cy+(-65)*s},{cx+ 50*s, cy+(-45)*s},
    {cx+ 60*s, cy+  15*s },{cx+  0*s, cy+  65*s },
    {cx+(-60)*s,cy+  15*s},{cx+(-50)*s,cy+(-45)*s}
};
D2D1_POINT_2F inner[6]={
    {cx+  0*s, cy+(-52)*s},{cx+ 40*s, cy+(-36)*s},
    {cx+ 48*s, cy+  12*s },{cx+  0*s, cy+  52*s },
    {cx+(-48)*s,cy+  12*s},{cx+(-40)*s,cy+(-36)*s}
};
auto MkPath=[&](D2D1_POINT_2F* pts,int n)->ID2D1PathGeometry*{
    ID2D1PathGeometry* pg=NULL;
    if(FAILED(g_d2F->CreatePathGeometry(&pg)))return NULL;
    ID2D1GeometrySink* sk=NULL;
    if(SUCCEEDED(pg->Open(&sk))){
        sk->BeginFigure(pts[0],D2D1_FIGURE_BEGIN_HOLLOW);
        for(int i=1;i<n;i++)sk->AddLine(pts[i]);
        sk->EndFigure(D2D1_FIGURE_END_CLOSED);sk->Close();sk->Release();
    }return pg;
};
auto Br=[&](float r,float gv,float b,float a)->ID2D1SolidColorBrush*{
    ID2D1SolidColorBrush*br=NULL;
    g_rT->CreateSolidColorBrush(D2D1::ColorF(r,gv,b,a),&br);return br;
};
ID2D1PathGeometry* pgO=MkPath(outer,6);
ID2D1PathGeometry* pgI=MkPath(inner,6);
ID2D1SolidColorBrush* glowBr=Br(0,1,1,0.118f);
if(glowBr&&pgO){g_rT->DrawGeometry(pgO,glowBr,18.0f*s);g_rT->DrawGeometry(pgO,glowBr,8.0f*s);glowBr->Release();}
ID2D1SolidColorBrush* innerBr=Br(0,1,1,0.353f);
if(innerBr&&pgI){g_rT->DrawGeometry(pgI,innerBr,1.5f*s);innerBr->Release();}
ID2D1SolidColorBrush* outerBr=Br(0,1,1,1.0f);
if(outerBr&&pgO){g_rT->DrawGeometry(pgO,outerBr,4.0f*s);outerBr->Release();}
if(pgO)pgO->Release();if(pgI)pgI->Release();
}

void RenderNotifications(){
    if(g_notifs.empty()){
        g_notifLastTick = 0;
        return;
    }
    DWORD now=GetTickCount();
    float dt=0.016f;
    if (g_notifLastTick > 0) {
        dt = (float)(now - g_notifLastTick) / 1000.f;
        if (dt < 0.f || dt > 0.1f) dt = 0.016f;
    }
    g_notifLastTick=now;
    float tY=NOTIF_TOP;
    for(size_t i=0;i<g_notifs.size();){
        Notif&n=g_notifs[i];
        n.elapsed+=dt;
        float tgt=tY;
        n.yAnim=n.yAnim+(tgt-n.yAnim)*0.25f;
        if(n.elapsed<NOTIF_FADE) n.alpha=n.elapsed/NOTIF_FADE;
        else if(n.elapsed>n.duration-NOTIF_FADE) n.alpha=(n.duration-n.elapsed)/NOTIF_FADE;
        else n.alpha=1.f;
        if(n.alpha<0.f)n.alpha=0.f;
        if(n.elapsed>=n.duration){g_notifs.erase(g_notifs.begin()+(int)i);continue;}
        float x=NOTIF_X,y=n.yAnim,w=NOTIF_W,h=NOTIF_H;
        float a=n.alpha;
        ID2D1SolidColorBrush*bg=NULL,*bd=NULL,*ht=NULL,*bt=NULL;
        if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(0.04f,0.06f,0.10f,0.85f*a),&bg))){
            g_rT->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x,y,x+w,y+h),8,8),bg);bg->Release();}
        if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.898f,1.0f,0.35f*a),&bd))){
            g_rT->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x,y,x+w,y+h),8,8),bd,1.0f);bd->Release();}
        /* Header (g_mTF, larger) — tight rect with CENTER paragraph for clean baseline */
        if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(1.0f,1.0f,1.0f,a),&ht))){
            if(g_mTF){D2D1_RECT_F r={x+12,y+10,x+w-6,y+32};
                g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                g_rT->DrawText(n.hdr,(UINT32)wcslen(n.hdr),g_mTF,r,ht);
                g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            }ht->Release();}
        /* Body (g_sTF, smaller) — directly below header */
        if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(0.7f,0.8f,0.9f,0.9f*a),&bt))){
            if(g_sTF){D2D1_RECT_F r={x+12,y+32,x+w-6,y+52};
                g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
                g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
                g_rT->DrawText(n.bdy,(UINT32)wcslen(n.bdy),g_sTF,r,bt);
                g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            }bt->Release();}
        /* Progress bar (track + green fill) — fração 0→1 da elapsed/duration */
        {
            float dur  = n.duration>0.f ? n.duration : NOTIF_DUR;
            float prog = n.elapsed / dur;
            if(prog<0.f) prog=0.f; else if(prog>1.f) prog=1.f;
            float bx=x+8, by=y+h-9, bx2=x+w-8, by2=y+h-4;
            ID2D1SolidColorBrush* pgT=NULL;
            if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(1.f,1.f,1.f,0.08f*a),&pgT))){
                g_rT->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(bx,by,bx2,by2),3,3),pgT);
                pgT->Release();
            }
            float fillX2 = bx + (bx2-bx)*prog;
            if(fillX2>bx){
                ID2D1SolidColorBrush* pgF=NULL;
                if(SUCCEEDED(g_rT->CreateSolidColorBrush(D2D1::ColorF(0.1f,0.85f,0.35f,0.9f*a),&pgF))){
                    g_rT->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(bx,by,fillX2,by2),3,3),pgF);
                    pgF->Release();
                }
            }
        }
        tY+=h+NOTIF_PAD;
        ++i;
    }
}

/* ── DX12Overlay — recursos D2D ─────────────────────────────────────────────── */
#ifdef SERAPH_BUILD_STUB
/* Stub não tem menu/InitUI — apenas a UI de login. Definir no-op local. */
static void InitUI(void) { /* no-op */ }
#else
extern void InitUI(void);   /* impl em gui_core.cpp (payload) */
#endif

bool DX12Overlay::Create(HWND h){
if(g_rT){g_rT->Release();g_rT=NULL;}
if(g_tF){g_tF->Release();g_tF=NULL;}
if(g_mTF){g_mTF->Release();g_mTF=NULL;}
if(g_sTF){g_sTF->Release();g_sTF=NULL;}
if(g_bTF){g_bTF->Release();g_bTF=NULL;}
if(g_dF){g_dF->Release();g_dF=NULL;}
if(g_d2F){g_d2F->Release();g_d2F=NULL;}
g_hW=h;g_r=true;g_lCk=false;g_lEr=false;g_lErT=0;GetClientRect(h,&g_sR);
#ifndef NDEBUG
FILE*lf=fopen("seraph_debug.log","a");
if(lf){fprintf(lf,"[TRACE] D2D1::Create - sR=%ldx%ld\n",g_sR.right,g_sR.bottom);fclose(lf);}
#endif
if(FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,&g_d2F))){
#ifndef NDEBUG
  {FILE*lf2=fopen("seraph_debug.log","a");if(lf2){fprintf(lf2,"[TRACE] FALHA: D2D1CreateFactory\n");fclose(lf2);}}
#endif
  return false;}
D2D1_RENDER_TARGET_PROPERTIES rtProps=D2D1::RenderTargetProperties(D2D1_RENDER_TARGET_TYPE_DEFAULT,D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM,D2D1_ALPHA_MODE_IGNORE));
D2D1_HWND_RENDER_TARGET_PROPERTIES hwndProps=D2D1::HwndRenderTargetProperties(h,D2D1::SizeU(g_sR.right,g_sR.bottom),D2D1_PRESENT_OPTIONS_IMMEDIATELY);
HRESULT hr=g_d2F->CreateHwndRenderTarget(&rtProps,&hwndProps,&g_rT);
#ifndef NDEBUG
{FILE*lf3=fopen("seraph_debug.log","a");if(lf3){fprintf(lf3,"[TRACE] CreateHwndRenderTarget hr=0x%08lX g_rT=%p\n",(unsigned long)hr,(void*)g_rT);fclose(lf3);}}
#endif
if(FAILED(hr))return false;
hr=g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.0f,0.0f,0.0f),&g_scratchBr);
if(FAILED(hr))return false;
if(FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED,__uuidof(IDWriteFactory),(IUnknown**)&g_dF))){
#ifndef NDEBUG
  {FILE*lf4=fopen("seraph_debug.log","a");if(lf4){fprintf(lf4,"[TRACE] FALHA: DWriteCreateFactory\n");fclose(lf4);}}
#endif
  return false;}
g_dF->CreateTextFormat(L"Segoe UI",NULL,DWRITE_FONT_WEIGHT_BOLD,  DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,18,L"",&g_tF);
g_dF->CreateTextFormat(L"Segoe UI",NULL,DWRITE_FONT_WEIGHT_BOLD,  DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,14,L"",&g_mTF);
g_dF->CreateTextFormat(L"Segoe UI",NULL,DWRITE_FONT_WEIGHT_BOLD,  DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,12,L"",&g_sTF);
g_dF->CreateTextFormat(L"Segoe UI",NULL,DWRITE_FONT_WEIGHT_REGULAR,DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL, 9,L"",&g_bTF);
#ifndef NDEBUG
{FILE*lf5=fopen("seraph_debug.log","a");if(lf5){fprintf(lf5,"[TRACE] D2D1::Create OK - tF=%p mTF=%p sTF=%p\n",(void*)g_tF,(void*)g_mTF,(void*)g_sTF);fclose(lf5);}}
#endif
InitUI();return true;}

void DX12Overlay::Destroy(){
g_r=false;
/* Destroy() é chamado em transições de overlay (system-check→login, login→menu),
 * NÃO apenas no shutdown.  Feature teardown real fica em gui.c ~502. */
if(g_scratchBr){g_scratchBr->Release();g_scratchBr=NULL;}
if(g_rT){g_rT->Release();g_rT=NULL;}
if(g_tF){g_tF->Release();g_tF=NULL;}
if(g_mTF){g_mTF->Release();g_mTF=NULL;}
if(g_sTF){g_sTF->Release();g_sTF=NULL;}
if(g_bTF){g_bTF->Release();g_bTF=NULL;}
if(g_dF){g_dF->Release();g_dF=NULL;}
if(g_d2F){g_d2F->Release();g_d2F=NULL;}
g_hW=NULL;}

void DX12Overlay::UpdateMouse(int x,int y,bool lDown){g_mX=x;g_mY=y;g_lD=lDown;}
void DX12Overlay::UpdateRightMouse(int x,int y,bool rDown){g_mX=x;g_mY=y;g_rD=rDown;}
void DX12Overlay::SetMenuVisible(bool v){g_mV=v;}
bool DX12Overlay::IsMenuVisible(){return g_mV;}
int  DX12Overlay::GetActiveTab(){return g_aT;}
void DX12Overlay::SetActiveTab(int t){g_aT=t;}
void DX12Overlay::Stop(){g_r=false;}
bool DX12Overlay::IsRunning(){return g_r;}
void DX12Overlay::SetSystemCheckResults(bool ts,bool sb,bool hvci){g_cT=ts;g_cS=sb;g_cH=hvci;}

/* ── RenderSystemCheck ───────────────────────────────────────────────────────── */
void DX12Overlay::RenderSystemCheck(){
if(!g_r||!g_rT)return;
g_rT->BeginDraw();
g_rT->Clear(D2D1::ColorF(0.05f,0.07f,0.11f));
D2D1_RECT_F pR={8,8,292,270};
ID2D1SolidColorBrush *pB=0,*nB=0,*dB=0,*sepB=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.07f,0.10f,0.16f),&pB);
if(pB)g_rT->FillRoundedRectangle(D2D1::RoundedRect(pR,12,12),pB);
static float pL=0;pL+=0.002f;float pV=0.7f+0.3f*sinf(pL);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.8f,1.0f,0.22f*pV),&nB);
if(nB)g_rT->DrawRoundedRectangle(D2D1::RoundedRect(pR,12,12),nB,1.5f);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.22f,0.32f,0.9f),&dB);
D2D1_RECT_F eaR={190,14,290,30};
if(dB)g_rT->FillRoundedRectangle(D2D1::RoundedRect(eaR,8,8),dB);
DT_C(L"EARLY ACCESS",eaR.left,eaR.top,eaR.right,eaR.bottom,0,0.75f,0.95f,1,g_sTF);
DrawEmblem(nB,66.0f);
DT_C(L"S E R A P H",0,102,300,126,1,1,1,1);
g_rT->CreateSolidColorBrush(D2D1::ColorF(1,1,1,0.07f),&sepB);
if(sepB){g_rT->DrawLine({20,140},{280,140},sepB,1.0f);sepB->Release();}
float cY=150;
DT(L"SecureBoot",22,cY,0.55f,0.65f,0.75f,1,g_mTF);
DT_C(!g_cS?L"Enabled":L"Disabled",175,cY,285,cY+22,g_cS?1.0f:0.2f,g_cS?0.3f:1.0f,g_cS?0.3f:0.5f,1,g_mTF);
cY+=24;
DT(L"HVCI",22,cY,0.55f,0.65f,0.75f,1,g_mTF);
DT_C(!g_cH?L"Enabled":L"Disabled",175,cY,285,cY+22,g_cH?1.0f:0.2f,g_cH?0.3f:1.0f,g_cH?0.3f:0.5f,1,g_mTF);
D2D1_RECT_F bR={18,222,282,262};
if(dB)g_rT->FillRoundedRectangle(D2D1::RoundedRect(bR,10,10),dB);
if(nB)g_rT->DrawRoundedRectangle(D2D1::RoundedRect(bR,10,10),nB,1.5f);
DT_C((!g_cH||!g_cS)?L"Apply Changes":L"Ready (Login)",bR.left,bR.top,bR.right,bR.bottom,0,0.9f,1,1);
if(pB)pB->Release();if(nB)nB->Release();if(dB)dB->Release();
g_rT->EndDraw();}

/* ── RenderLoading ───────────────────────────────────────────────────────────── */
void DX12Overlay::RenderLoading(const wchar_t* t){
if(!g_r||!g_rT)return;
g_rT->BeginDraw();
g_rT->Clear(D2D1::ColorF(0.071f,0.086f,0.122f));
{ID2D1LinearGradientBrush*lb=NULL;ID2D1GradientStopCollection*sc=NULL;
D2D1_GRADIENT_STOP gs[4]={{0.0f,D2D1::ColorF(0,0,0,0)},{0.3f,D2D1::ColorF(0.0f,0.824f,0.902f,0.65f)},{0.7f,D2D1::ColorF(0.0f,0.824f,0.902f,0.65f)},{1.0f,D2D1::ColorF(0,0,0,0)}};
g_rT->CreateGradientStopCollection(gs,4,&sc);
if(sc){g_rT->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties({50.f,10.f},{250.f,10.f}),sc,&lb);sc->Release();}
if(lb){g_rT->DrawLine({50.f,10.f},{250.f,10.f},lb,2.5f);lb->Release();}}
{D2D1_RECT_F br={100,18,204,32};
ID2D1SolidColorBrush*bg=0,*bd=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.06f),&bg);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.14f),&bd);
if(bg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(br,99,99),bg);bg->Release();}
if(bd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(br,99,99),bd,1.0f);bd->Release();}
DT_C(L"EARLY ACCESS",br.left,br.top,br.right,br.bottom,0.0f,0.824f,0.902f,0.65f,g_sTF);}
{static float aL=0;aL+=0.002f;DrawEmblem(NULL,80.0f);}
DT_C(L"S E R A P H",0,122,300,144,0.796f,0.835f,0.878f,1.0f);
{ID2D1LinearGradientBrush*lb=NULL;ID2D1GradientStopCollection*sc=NULL;
D2D1_GRADIENT_STOP gs2[4]={{0.0f,D2D1::ColorF(0,0,0,0)},{0.12f,D2D1::ColorF(0.0f,0.824f,0.902f,0.12f)},{0.88f,D2D1::ColorF(0.0f,0.824f,0.902f,0.12f)},{1.0f,D2D1::ColorF(0,0,0,0)}};
g_rT->CreateGradientStopCollection(gs2,4,&sc);
if(sc){g_rT->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties({0.f,180.f},{300.f,180.f}),sc,&lb);sc->Release();}
if(lb){g_rT->DrawLine({0.f,180.f},{300.f,180.f},lb,1.0f);lb->Release();}}
DT_C(t,20,230,280,258,0.392f,0.549f,0.647f,0.85f,g_sTF);
{static float sp=0;sp+=0.025f;if(sp>1.0f)sp-=1.0f;
ID2D1SolidColorBrush*tb=0,*sb=0;
D2D1_RECT_F track={40,282,260,294};
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.12f),&tb);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.7f),&sb);
if(tb){g_rT->FillRoundedRectangle(D2D1::RoundedRect(track,6,6),tb);tb->Release();}
float headX=40.0f+sp*220.0f;float hw=50.0f;
float hL=(headX-hw<40.0f)?40.0f:headX-hw;float hR=(headX>260.0f)?260.0f:headX;
if(hR>hL&&sb){D2D1_RECT_F hr={hL,282,hR,294};g_rT->FillRoundedRectangle(D2D1::RoundedRect(hr,6,6),sb);}
if(sb)sb->Release();}
g_rT->EndDraw();}

/* ── RenderLogin ─────────────────────────────────────────────────────────────── */
void DX12Overlay::RenderLogin(){
    static bool loggedStart = false;
    if (!loggedStart) {
        loggedStart = true;
        WriteLogFile("RenderLogin: first call start");
    }
if(!g_r||!g_rT)return;
g_rT->BeginDraw();
g_rT->Clear(D2D1::ColorF(0.071f,0.086f,0.122f));
{bool hx=(g_mX>=274&&g_mX<=292&&g_mY>=6&&g_mY<=28);
ID2D1SolidColorBrush*xb=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.898f,1.0f,hx?1.0f:0.4f),&xb);
if(xb&&g_sTF){D2D1_RECT_F r={274,6,292,28};
g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
g_rT->DrawText(L"X",1,g_sTF,r,xb);
g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);xb->Release();}}
{ID2D1LinearGradientBrush*lb=NULL;ID2D1GradientStopCollection*sc=NULL;
D2D1_GRADIENT_STOP gs[4]={{0.0f,D2D1::ColorF(0,0,0,0)},{0.3f,D2D1::ColorF(0.0f,0.824f,0.902f,0.65f)},{0.7f,D2D1::ColorF(0.0f,0.824f,0.902f,0.65f)},{1.0f,D2D1::ColorF(0,0,0,0)}};
g_rT->CreateGradientStopCollection(gs,4,&sc);
if(sc){g_rT->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties({50.f,10.f},{250.f,10.f}),sc,&lb);sc->Release();}
if(lb){g_rT->DrawLine({50.f,10.f},{250.f,10.f},lb,2.5f);lb->Release();}}
{D2D1_RECT_F br={100,18,204,32};
ID2D1SolidColorBrush*bg=0,*bd=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.06f),&bg);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,0.14f),&bd);
if(bg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(br,99,99),bg);bg->Release();}
if(bd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(br,99,99),bd,1.0f);bd->Release();}
DT_C(L"EARLY ACCESS",br.left,br.top,br.right,br.bottom,0.0f,0.824f,0.902f,0.65f,g_sTF);}
{static float aL=0;aL+=0.002f;DrawEmblem(NULL,80.0f);}
DT_C(L"S E R A P H",0,122,300,144,0.796f,0.835f,0.878f,1.0f);
DT_C(L"Authentication Required",0,144,300,162,0.392f,0.510f,0.627f,0.68f,g_sTF);
{ID2D1LinearGradientBrush*lb=NULL;ID2D1GradientStopCollection*sc=NULL;
D2D1_GRADIENT_STOP gs[4]={{0.0f,D2D1::ColorF(0,0,0,0)},{0.12f,D2D1::ColorF(0.0f,0.824f,0.902f,0.12f)},{0.88f,D2D1::ColorF(0.0f,0.824f,0.902f,0.12f)},{1.0f,D2D1::ColorF(0,0,0,0)}};
g_rT->CreateGradientStopCollection(gs,4,&sc);
if(sc){g_rT->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties({0.f,180.f},{300.f,180.f}),sc,&lb);sc->Release();}
if(lb){g_rT->DrawLine({0.f,180.f},{300.f,180.f},lb,1.0f);lb->Release();}}
DT(L"USERNAME",20,196,0.392f,0.549f,0.647f,0.9f,g_sTF);
{D2D1_RECT_F fr={20,214,280,254};
ID2D1SolidColorBrush*fbg=0,*fbd=0;bool foc=(g_lFc==0);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.03f,0.04f,0.06f,1.0f),&fbg);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,foc?0.35f:0.10f),&fbd);
if(fbg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(fr,10,10),fbg);fbg->Release();}
if(fbd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(fr,10,10),fbd,foc?1.8f:1.0f);fbd->Release();}
g_rT->PushAxisAlignedClip(D2D1::RectF(32,fr.top+4,fr.right-10,fr.bottom-4),D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
if(g_lU[0])DT(g_lU,32,226,0.796f,0.835f,0.878f,1.0f,g_mTF);
else DT(L"Enter username",32,226,0.22f,0.27f,0.32f,1.0f,g_mTF);
g_rT->PopAxisAlignedClip();}
DT(L"LICENSE KEY",20,272,0.392f,0.549f,0.647f,0.9f,g_sTF);
{D2D1_RECT_F fr={20,290,280,330};
ID2D1SolidColorBrush*fbg=0,*fbd=0;bool foc=(g_lFc==1);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.03f,0.04f,0.06f,1.0f),&fbg);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,foc?0.35f:0.10f),&fbd);
if(fbg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(fr,10,10),fbg);fbg->Release();}
if(fbd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(fr,10,10),fbd,foc?1.8f:1.0f);fbd->Release();}
g_rT->PushAxisAlignedClip(D2D1::RectF(32,fr.top+4,fr.right-10,fr.bottom-4),D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
if(g_lK[0])DT(g_lK,32,302,0.796f,0.835f,0.878f,1.0f,g_mTF);
else DT(L"Enter license key",32,302,0.22f,0.27f,0.32f,1.0f,g_mTF);
g_rT->PopAxisAlignedClip();}
{D2D1_RECT_F br={70,358,230,390};
bool bH=(g_mX>=(int)br.left&&g_mX<=(int)br.right&&g_mY>=(int)br.top&&g_mY<=(int)br.bottom);
ID2D1SolidColorBrush*bbg=0,*bbd=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,bH?0.26f:0.18f),&bbg);
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.824f,0.902f,bH?0.55f:0.35f),&bbd);
if(bbg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(br,10,10),bbg);bbg->Release();}
if(bbd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(br,10,10),bbd,1.5f);bbd->Release();}
DT_C(L"LOGIN",br.left,br.top,br.right,br.bottom,0.0f,0.824f,0.902f,bH?1.0f:0.85f);}
if(g_lEr){
g_lErT+=0.016f;
float ea=1.0f;if(g_lErT>2.5f)ea=1.0f-(g_lErT-2.5f)*2.0f;
if(g_lErT>3.0f){g_lEr=false;g_lErT=0;}
else{ID2D1SolidColorBrush*eB=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.6f,0.05f,0.05f,0.52f*ea),&eB);
D2D1_RECT_F er={20,166,280,194};
if(eB){g_rT->FillRoundedRectangle(D2D1::RoundedRect(er,6,6),eB);eB->Release();}
ID2D1SolidColorBrush*acc=0;g_rT->CreateSolidColorBrush(D2D1::ColorF(1.0f,0.25f,0.25f,0.7f*ea),&acc);
if(acc){g_rT->FillRoundedRectangle(D2D1::RoundedRect({20,166,24,194},3,3),acc);acc->Release();}
DT_C(g_lErMsg,28,166,280,194,1,0.75f,0.75f,ea,g_sTF);}}
if(g_lSt){
g_lStT+=0.016f;
float sa=1.0f;if(g_lStT>2.5f)sa=1.0f-(g_lStT-2.5f)*2.0f;
if(g_lStT>3.0f){g_lSt=false;g_lStT=0;}
else{ID2D1SolidColorBrush*sB=0;
g_rT->CreateSolidColorBrush(D2D1::ColorF(0.04f,0.28f,0.08f,0.55f*sa),&sB);
D2D1_RECT_F sr={20,166,280,194};
if(sB){g_rT->FillRoundedRectangle(D2D1::RoundedRect(sr,6,6),sB);sB->Release();}
ID2D1SolidColorBrush*sacc=0;g_rT->CreateSolidColorBrush(D2D1::ColorF(0.2f,1.0f,0.35f,0.8f*sa),&sacc);
if(sacc){g_rT->FillRoundedRectangle(D2D1::RoundedRect({20,166,24,194},3,3),sacc);sacc->Release();}
DT_C(g_lStMsg,28,166,280,194,0.3f,1.0f,0.5f,sa,g_sTF);}}
g_rT->EndDraw();
    static bool loggedEnd = false;
    if (!loggedEnd) {
        loggedEnd = true;
        WriteLogFile("RenderLogin: first call end finished successfully");
    }
}

/* ── extern "C" wrappers ─────────────────────────────────────────────────────── */
extern "C" {

BOOL Overlay_Create(HWND hWnd){
    LoadConfig();
    return DX12Overlay::Create(hWnd)?TRUE:FALSE;
}
void Overlay_Destroy(void){ DX12Overlay::Destroy(); }
void Overlay_Stop(void)   { DX12Overlay::Stop(); }
BOOL Overlay_IsRunning(void){ return DX12Overlay::IsRunning()?TRUE:FALSE; }

void Overlay_UpdateMouse(int x,int y,BOOL lD){DX12Overlay::UpdateMouse(x,y,!!lD);}
void Overlay_SetSystemCheckResults(BOOL ts,BOOL sb,BOOL hvci){DX12Overlay::SetSystemCheckResults(!!ts,!!sb,!!hvci);}

void Overlay_RenderLogin(void)      { DX12Overlay::RenderLogin(); }
void Overlay_RenderSystemCheck(void){ DX12Overlay::RenderSystemCheck(); }
void Overlay_RenderLoading(const wchar_t* t){ DX12Overlay::RenderLoading(t); }

void Overlay_LoginChar(wchar_t c){
    if(c<32||c>126)return;
    wchar_t*b=g_lFc==0?g_lU:g_lK;
    int mx=g_lFc==0?20:127;
    int l=(int)wcslen(b);
    if(l<mx){b[l]=c;b[l+1]=0;}
}
void Overlay_LoginBackspace(void){
    wchar_t*b=g_lFc==0?g_lU:g_lK;
    int l=(int)wcslen(b);if(l>0)b[l-1]=0;
}
void Overlay_LoginSetFocus(int f)   {g_lFc=f;}
void Overlay_LoginToggleFocus(void) {g_lFc=g_lFc==0?1:0;}
void Overlay_LoginClick(void)       {g_lCk=true;}
BOOL Overlay_LoginWasClicked(void)  {if(g_lCk){g_lCk=false;return TRUE;}return FALSE;}
void Overlay_LoginShowError(void)   {wcsncpy(g_lErMsg,L"Invalid credentials",63);g_lEr=true;g_lErT=0;}
void Overlay_LoginShowErrorMsg(const wchar_t*msg){if(msg){wcsncpy(g_lErMsg,msg,63);g_lErMsg[63]=0;}g_lEr=true;g_lErT=0;}
void Overlay_LoginShowStatusMsg(const wchar_t*msg){if(msg){wcsncpy(g_lStMsg,msg,63);g_lStMsg[63]=0;}g_lSt=true;g_lStT=0;}
void Overlay_LoginSetCreds(const wchar_t*u,const wchar_t*k){if(u){wcsncpy(g_lU,u,20);g_lU[20]=0;}if(k){wcsncpy(g_lK,k,127);g_lK[127]=0;}}
void Overlay_LoginGetCreds(wchar_t*u,int uM,wchar_t*k,int kM){if(u){wcsncpy(u,g_lU,uM-1);u[uM-1]=0;}if(k){wcsncpy(k,g_lK,kM-1);k[kM-1]=0;}}
int  Overlay_LoginGetFocus(void){ return g_lFc; }

void Overlay_AddNotification(const wchar_t*header,const wchar_t*body){
    if(!header||!body)return;
    Notif n={};
    wcsncpy_s(n.hdr,80,header,_TRUNCATE);
    wcsncpy_s(n.bdy,160,body,_TRUNCATE);
    n.elapsed=0.f;n.duration=NOTIF_DUR;
    float startY=NOTIF_TOP+(float)g_notifs.size()*(NOTIF_H+NOTIF_PAD);
    n.yAnim=startY+NOTIF_H;n.alpha=0.f;
    g_notifs.push_back(n);
}
void Overlay_AddNotificationEx(const wchar_t*header,const wchar_t*body,float durSec){
    if(!header||!body)return;
    Notif n={};
    wcsncpy_s(n.hdr,80,header,_TRUNCATE);
    wcsncpy_s(n.bdy,160,body,_TRUNCATE);
    n.elapsed=0.f;n.duration=durSec>0.f?durSec:NOTIF_DUR;
    float startY=NOTIF_TOP+(float)g_notifs.size()*(NOTIF_H+NOTIF_PAD);
    n.yAnim=startY+NOTIF_H;n.alpha=0.f;
    g_notifs.push_back(n);
}

void Overlay_SetStreamProofWindow(HWND hWnd,BOOL enable){
    if(enable){g_streamProofHwnd=hWnd;}
    else{g_espStreamProofHwnd=hWnd;}
    ApplyStreamProof(hWnd,enable?L"menu":L"esp");
}
void Overlay_LoadConfigSettings(void){ LoadConfig(); }
void Overlay_SaveConfig(void)        { SaveConfig(); }

int  Overlay_GetMenuHotkey(void)   { return g_menuHotkey; }
int  Overlay_GetFlyHotkey(void)    { return g_flyHotkey; }
int  Overlay_GetFlyDirHotkey(void) { return g_flyDirHotkey; }
int  Overlay_GetGsHotkey(void)     { return g_gsHotkey; }
int  Overlay_GetAimbotHotkey(void) { return g_aimbotHotkey; }
int  Overlay_GetSuicideHotkey(void){ return g_suicideHotkey; }
int  Overlay_GetAimbotTargetHeadHotkey(void){ return g_aimbotTargetHeadHotkey; }
int  Overlay_GetFuserHotkey(void)           { return g_fuserHotkey; }
int  Overlay_GetOpkHotkey(void)             { return g_opkHotkey; }

} /* extern "C" */
