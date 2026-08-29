#include <windows.h>
#define SERAPH_MARATHON
#include "d2d_engine.h"  /* motor D2D puro — Create/Destroy/RenderLogin/RenderSystemCheck/RenderLoading + Login* + Config */
#include "gui_core.h"
#include "gui.h"
#include "Resource.h"
#include "config_crypto.h"
#include "debug.h"
extern "C" {
#include "syscalls.h"   /* SeraphSleep, SeraphCreateThread, SysNtClose */
#include "antire.h"     /* AntiRE_Start — monitoramento de ferramentas RE */
#include "evasion_user.h" /* UeErasePEHeader */
}
#include "attach.h"
#include "patch.h"
#include "d2_patches.h"
#include "cave_finder.h"
#include "fly.h"
/* #include "ammo.h" -- disabled: patterns outdated, pending AOB update */
#include "gamespeed.h"
#include "damage.h"
#include "guardian.h"
#include "health_regen.h"
#include "noturnback.h"
#include "nojoinallies.h"
#include "noinactivity.h"
#include "immune_boss.h"
#include "interact_aura.h"
#include "instakill.h"
#include "rapid_fire.h"
#include "infinite_ammo.h"
#include "ammo_brick.h"
#include "handling_speed.h"
#include "bunnyhop.h"
#include "movespeed.h"
#include "local_player.h"
#include "skeleton.h"
#include "player_cloner.h"
#include "namechanger.h"
#include "revive.h"
#include "opk.h"
#include "instant_abilities.h"
#include "kill_aura.h"
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
#include "aura.h"
#endif
#include "byovd.h"
extern "C" {
#include "byovd_lock.h"
}
#include "lazyhook.h"
#include "lists.h"
#include "aob_cache.h"
#include "esp.h"
#include "esp_overlay.h"
#include "teleports.h"
#include "aimbot.h"
#include "controller_input.h"
#include "silent_aim.h"
#include "no_recoil.h"
#include "suicide.h"
#include "matchmaking.h"
#include "activity_loader.h"
#ifdef SERAPH_DMA_BUILD
#include "seraph_kmbox.h"
#include "seraph_fuser.h"
#endif
#include <vector>
#include <string>
#include <map>
#include <dwrite.h>
#include <d2d1.h>
#include <cmath>
#include "XorStr.h"
#include <fstream>
#include <filesystem>
#include "json.hpp"
#include <shlobj.h>
#pragma comment(lib,"d2d1.lib")
#pragma comment(lib,"dwrite.lib")
#pragma comment(lib,"bcrypt.lib")

/* ── Runtime string decryption (XOR key 0xA5) ── */
static const wchar_t* SX(const unsigned short* e, int n) {
    thread_local static wchar_t p[8][256]; thread_local static int idx=0;
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
/* "Cheat initialized" */
static const unsigned short k_cheat_init[]={0xE6,0xCD,0xC0,0xC4,0xD1,0x85,0xCC,0xCB,0xCC,0xD1,0xCC,0xC4,0xC9,0xCC,0xDF,0xC0,0xC1};
/* "SERAPH" (title, uppercase) */
static const unsigned short k_seraph_uc[] ={0xF6,0xE0,0xF7,0xE4,0xF5,0xED};
/* "Configs" */
static const unsigned short k_configs_dir[] = {0xe6, 0xca, 0xcb, 0xc3, 0xcc, 0xc2, 0xd6};
/* "\\Seraph\\TP_Configs" */
static const unsigned short k_tp_configs_path[] = {0xf9, 0xf6, 0xc0, 0xd7, 0xc4, 0xd5, 0xcd, 0xf9, 0xf1, 0xf5, 0xfa, 0xe6, 0xca, 0xcb, 0xc3, 0xcc, 0xc2, 0xd6};
/* "Some features unavailable - try reattach" */
static const unsigned short k_reattach_msg[] = {0xf6, 0xca, 0xc8, 0xc0, 0x85, 0xc3, 0xc0, 0xc4, 0xd1, 0xd0, 0xd7, 0xc0, 0xd6, 0x85, 0xd0, 0xcb, 0xc4, 0xd3, 0xc4, 0xcc, 0xc9, 0xc4, 0xc7, 0xc9, 0xc0, 0x85, 0x88, 0x85, 0xd1, 0xd7, 0xdc, 0x85, 0xd7, 0xc0, 0xc4, 0xd1, 0xd1, 0xc4, 0xc6, 0xcd};

/* ── Globals migrados para d2d_engine.cpp — extern para uso no RenderMenu/CM ── */
extern HWND                   g_hW;
extern IDWriteFactory*        g_dF;
extern IDWriteTextFormat*     g_tF;
extern IDWriteTextFormat*     g_sTF;
extern IDWriteTextFormat*     g_mTF;
extern IDWriteTextFormat*     g_bTF;
extern ID2D1Factory*          g_d2F;
extern ID2D1HwndRenderTarget* g_rT;
extern RECT                   g_sR;
extern bool                   g_r;
extern bool                   g_mV;
extern int                    g_mX, g_mY;
extern bool                   g_lD;
extern bool                   g_rD;
extern int                    g_aT;
extern bool                   g_streamProof;
extern int                    g_menuHotkey;
extern int                    g_flyHotkey;
extern int                    g_flyDirHotkey;
extern int                    g_gsHotkey;
extern int                    g_aimbotHotkey;
extern int                    g_aimbotTargetHeadHotkey;
extern int                    g_suicideHotkey;
extern bool                   g_waitingForKey;
extern bool                   g_waitingForFlyKey;
extern bool                   g_waitingForFlyDirKey;
extern bool                   g_waitingForGsKey;
extern bool                   g_waitingForAimbotKey;
extern bool                   g_waitingForAimbotTargetHeadKey;
extern bool                   g_waitingForSuicideKey;
extern bool                   g_waitingForFuserKey;
extern int                    g_fuserHotkey;
extern int                    g_opkHotkey;
#ifdef SERAPH_DMA_BUILD
static bool                   g_fuserActive = false;
static bool                   g_kmHwAim = true;
static bool                   g_kmAutoConn = false;
static bool                   g_showKmBoxSetup = false;
static wchar_t                g_kmBufIp[32] = {};
static wchar_t                g_kmBufPort[16] = {};
static wchar_t                g_kmBufUuid[64] = {};
static wchar_t                g_kmBufCom[32] = {};
static wchar_t                g_kmBufBaud[16] = {};
static int                    g_kmBufIpLen = 0;
static int                    g_kmBufPortLen = 0;
static int                    g_kmBufUuidLen = 0;
static int                    g_kmBufComLen = 0;
static int                    g_kmBufBaudLen = 0;
static wchar_t                g_kmFocusTag[16] = {};
static float                  g_kmBoxFade = 0.0f;
static RECT                   g_kmModalR = {};
static RECT                   g_kmCloseR = {};
static RECT                   g_kmConnR  = {};
static RECT                   g_kmDiscR  = {};
static RECT                   g_kmDevR   = {};
static RECT                   g_kmIpR    = {};
static RECT                   g_kmPortR  = {};
static RECT                   g_kmUuidR  = {};
static RECT                   g_kmComR   = {};
static RECT                   g_kmBaudR  = {};

static void KmBox_Utf8ToWide(const char *src, wchar_t *dst, int dstChars, int *outLen)
{
    if (!dst || dstChars <= 0) { if (outLen) *outLen = 0; return; }
    dst[0] = 0;
    if (!src || !src[0]) { if (outLen) *outLen = 0; return; }
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, dstChars);
    if (outLen) *outLen = (int)wcslen(dst);
}

static void KmBox_WideToUtf8(const wchar_t *src, char *dst, int dstBytes)
{
    if (!dst || dstBytes <= 0) return;
    dst[0] = 0;
    if (!src || !src[0]) return;
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstBytes, NULL, NULL);
}

static void KmBox_LoadUiBuffers(void)
{
    SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
    KmBox_Utf8ToWide(km->ip, g_kmBufIp, 32, &g_kmBufIpLen);
    KmBox_Utf8ToWide(km->port, g_kmBufPort, 16, &g_kmBufPortLen);
    KmBox_Utf8ToWide(km->uuid, g_kmBufUuid, 64, &g_kmBufUuidLen);
    KmBox_Utf8ToWide(km->com_port, g_kmBufCom, 32, &g_kmBufComLen);
    KmBox_Utf8ToWide(km->baud_str, g_kmBufBaud, 16, &g_kmBufBaudLen);
}

static void KmBox_SaveUiBuffers(void)
{
    SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
    KmBox_WideToUtf8(g_kmBufIp, km->ip, sizeof(km->ip));
    KmBox_WideToUtf8(g_kmBufPort, km->port, sizeof(km->port));
    KmBox_WideToUtf8(g_kmBufUuid, km->uuid, sizeof(km->uuid));
    KmBox_WideToUtf8(g_kmBufCom, km->com_port, sizeof(km->com_port));
    KmBox_WideToUtf8(g_kmBufBaud, km->baud_str, sizeof(km->baud_str));
}

static BOOL KmBox_GetFieldBuf(const wchar_t *tag, wchar_t **buf, int *maxLen, int **lenPtr)
{
    if (!tag || !buf || !maxLen || !lenPtr) return FALSE;
    if (!wcscmp(tag, L"km_ip"))   { *buf = g_kmBufIp;   *maxLen = 31; *lenPtr = &g_kmBufIpLen;   return TRUE; }
    if (!wcscmp(tag, L"km_port")) { *buf = g_kmBufPort; *maxLen = 15; *lenPtr = &g_kmBufPortLen; return TRUE; }
    if (!wcscmp(tag, L"km_uuid")) { *buf = g_kmBufUuid; *maxLen = 63; *lenPtr = &g_kmBufUuidLen; return TRUE; }
    if (!wcscmp(tag, L"km_com"))  { *buf = g_kmBufCom;  *maxLen = 31; *lenPtr = &g_kmBufComLen;  return TRUE; }
    if (!wcscmp(tag, L"km_baud")) { *buf = g_kmBufBaud; *maxLen = 15; *lenPtr = &g_kmBufBaudLen; return TRUE; }
    return FALSE;
}
#endif

/* g_dF / g_rT / g_d2F / g_tF / g_hW / g_r / g_mV / g_sR / g_lD / g_streamProof* migrados para d2d_engine.cpp */
static DWORD g_spLastToggle=0;
static bool  g_patchActive[64]={};
static bool  g_gsActive=false;    /* Game Speed feature expanded */
static bool  g_dmgActive=false;   /* Damage Increase feature expanded */
static bool  g_guardianActive=false; /* Guardian Size feature expanded */
static int   g_gsSpeed=1;   /* Game Speed slider 1-100 */
static int   g_gsSlow=1;    /* Game Slow  slider 1-10  */
static int   g_dmgValue=100; /* Damage multiplier 1-1000 */
static bool  g_killAuraActive=false;
static int   g_killAuraValue=100;
static bool  g_opkActive=false;
static int   g_opkDistance=3;
static bool  g_waitingForOpkKey=false;
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
static bool  g_auraActive=false;
static int   g_auraValue=100;
#endif
static bool  g_immuneBossActive=false;
static bool  g_instakillActive=false;
static bool  g_itarActive=false;
static bool  g_bhopActive=false;
static int   g_bhopSpeed=20;
static int   g_bhopVertical=10;
static bool  g_reviveActive=false;
static bool  g_msActive=false;       /* Movement Speed toggle          */
static int   g_msValue=5;            /* Movement Speed value 1..10     */
/* static bool  g_chamsActive=false;  // CHAMS: temporarily disabled */
bool  g_espActive=false;    /* ESP overlay (entity boxes) toggle */
bool  g_espTeamCheck=false;  /* FALSE = show all boxes by default */
bool  g_aimbotActive=false; /* Aimbot toggle */
int   g_aimbotSmooth=50;    /* Aimbot smoothing slider 1-100 (default=50≈smooth 8.0) */
bool  g_aimbotShowFov=false; /* Show FOV circle toggle */
int   g_aimbotFovSize=50;    /* FOV size slider 1-100 (default=50≈328px) */
bool  g_aimbotHeadTarget=true; /* TRUE=aim head, FALSE=aim body */
static bool  g_aimbotSwitchDelayActive=false; /* enable switch delay */
static int   g_aimbotSwitchDelayVal=5;        /* 0..20 → 0.0..2.0s (step 0.1, default 0.5s) */
static bool  g_aimbotMemoryAim=false;         /* Pitch/yaw writes (no mouse) */
bool  g_aimbotTeamCheck=false;         /* FALSE = aimbot targets all entities by default */
#ifdef SERAPH_DMA_BUILD
static bool  g_aimbotVisCheck=false;          /* DMA: NaN vis gate toggle */
#endif
#ifndef NDEBUG
static bool  g_aimbotVisCheckActive=false;    /* dev: enable NaN vis gate       */
static bool  g_activityLoaderActive=false;
static int   g_activityIdValue=0;
#endif
static bool  g_espMasterActive=false;          /* ESP master toggle              */
static bool  g_skeletonActive=false;          /* skeleton ESP toggle            */
static bool  g_espDrawHealth=false;           /* Health ESP toggle              */
static bool  g_espDrawShield=false;           /* Shield ESP toggle              */
static bool  g_espDrawDistance=false;         /* Distance ESP toggle            */
static bool  g_espDrawName=false;             /* Name ESP toggle                */
static bool  g_matchmakingActive=false;       /* matchmaking list toggle         */
static bool  g_rofActive=false;
static bool  g_hsActive=false;
static int   g_hsMult=2;    /* slider 1..10 → float 1.0..10.0 */
static bool  g_ammoActive=false;
static bool  g_ammoBrickActive=false;
static bool  g_clonerActive=false;
static int   g_rofMult=5;   /* slider 1..10 (1=no boost, 10=max). mult = 1.0 - (s-1)*0.7/9 */
static bool  g_silentActive=false; /* Silent Aim toggle */
static int   g_silentValue=100;     /* Silent Aim slider 1-100 = cone degrees */
static bool  g_noRecoilActive=false; /* No Recoil toggle */
static bool  g_flyActive=false;    /* Fly WASD toggle */
static int   g_flySpeed=5;         /* Fly WASD speed slider 1-10 */
static bool  g_flyDirActive=false; /* Fly Directional toggle */
static int   g_flyDirSpeed=5;      /* Fly Directional speed slider 1-10 */
static int   g_guardianValue=100; /* Guardian size: -100..200 -> -1.00..2.00 float */
static int   g_stackCount=100;
static bool  g_ncActive=false;
static wchar_t g_ncNameBuf[32]={};
static int   g_ncNameLen=0;
static bool  g_ncNameFocused=false;
static bool  g_showLoadConfigWindow = false;
static wchar_t g_tpNameBuf[32] = {};
static int     g_tpNameLen = 0;
static bool    g_tpNameFocused = false;
static bool    g_waitingForTpKey = false;
static int     g_tpWaitingSlot = -1;
static bool  g_showSaveConfigWindow = false;
/* ── TP Config modal (overlay with fade, like KmBox setup) ───────────── */
static bool    g_showTpConfigModal = false; /* false=none, true=shown */
static int     g_tpConfigModalMode = 0;     /* 1=load, 2=save */
static float   g_tpConfigFade = 0.0f;
static RECT    g_tpModalR = {};
static RECT    g_tpCloseR = {};
static RECT    g_tpSaveR  = {};
static RECT    g_tpInputR = {};
static wchar_t g_tpCfgNameBuf[32] = {};
static int     g_tpCfgNameLen = 0;
static bool    g_tpCfgNameFocused = false;
static wchar_t g_cfgNameBuf[32] = {};
static int   g_cfgNameLen = 0;
static bool  g_cfgNameFocused = false;
static std::string g_currentConfigName = "default";
static int*  g_numFocus=nullptr;
static wchar_t g_numBuf[8]=L"100";
static int   g_numBufLen=3;
/* g_mX / g_mY / g_lD / g_aT / hotkeys / g_sR / g_lU / g_lK / g_mV migrados para d2d_engine.cpp */
static bool g_dS=false;     /* slider drag state */
static int  g_dSI=-1;       /* slider drag index */
static bool g_showFlyHotkey=false;
static bool g_showFlyDirHotkey=false;
struct UE{enum T{TabButton,Toggle,Slider,Label,NumberInput,TextInput}t;RECT r;bool* s;int* v;int min,max;std::wstring txt;};
static std::map<int,std::vector<UE>> g_tE;
extern "C" HWND g_hMainWnd;

/* Notif system + g_notifs migrados para d2d_engine.cpp */
/* NOTIF_HOTKEY_DUR acessado via Overlay_AddNotificationEx — sem referência direta aqui */
static const float NOTIF_HOTKEY_DUR = 1.5f;

/* D2DEngine_TickStreamProof — chamado por RenderMenu a cada frame */
extern void D2DEngine_TickStreamProof(void);

/* DR / DT / DT_C / DTail / RenderNotifications — definidas static abaixo (locais ao RenderMenu) */

/* UpS / ReqX permanecem aqui — usados por CM() */
static void UpS(UE& e,int x){float p=(float)(x-e.r.left)/(e.r.right-e.r.left);if(p<0)p=0;if(p>1)p=1;*e.v=e.min+(int)(p*(e.max-e.min));}
static void ReqX(){DX12Overlay::Stop();if(g_hMainWnd)PostMessage(g_hMainWnd,WM_QUIT,0,0);}

/* SaveConfig / LoadConfig / ApplyStreamProof / TickStreamProof em d2d_engine.cpp */
extern void Overlay_SaveConfig(void);  /* d2d_engine.cpp — chamado ao mudar hotkeys */
extern void LoadConfig(void);  /* d2d_engine.cpp */

static std::wstring GetConfigDir() {
    wchar_t docPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, docPath))) {
        std::filesystem::path p = std::filesystem::path(docPath) / SX(k_seraph_hdr, 6) / SX(k_configs_dir, 7);
        std::filesystem::create_directories(p);
        return p.wstring();
    }
    return L"";
}

static std::vector<std::wstring> GetConfigList() {
    std::vector<std::wstring> list;
    std::wstring dir = GetConfigDir();
    if (!dir.empty()) {
        try {
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (entry.is_regular_file() && entry.path().extension() == L".json") {
                    list.push_back(entry.path().stem().wstring());
                }
            }
        } catch (...) {}
    }
    return list;
}

static bool IsEspOverlayNeeded(void) {
    return (g_espMasterActive || g_espActive || g_aimbotActive || g_skeletonActive || g_matchmakingActive || g_espDrawHealth || g_espDrawShield || g_espDrawDistance || g_espDrawName);
}

static void ApplyLoadedSettings() {
    Fly_SetEnabled(g_flyActive ? TRUE : FALSE);
    FlyDir_SetEnabled(g_flyDirActive ? TRUE : FALSE);
    if (!g_gsActive) {
        GameSpeed_SetSpeed(1);
        GameSpeed_SetSlow(1);
        g_gsSpeed = 1;
        g_gsSlow = 1;
    } else {
        GameSpeed_SetSpeed(g_gsSpeed);
        GameSpeed_SetSlow(g_gsSlow);
    }
    Damage_SetEnabled(g_dmgActive ? TRUE : FALSE);
    if (g_dmgActive) Damage_SetMultiplier(g_dmgValue);
    KillAura_SetEnabled(g_killAuraActive ? TRUE : FALSE);
    if (g_killAuraActive) KillAura_SetMultiplier(g_killAuraValue);
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
    Aura_SetEnabled(g_auraActive ? TRUE : FALSE);
    if (g_auraActive) Aura_SetMultiplier(g_auraValue);
#endif
    ImmuneBoss_SetEnabled(g_immuneBossActive ? TRUE : FALSE);
    InstaKill_SetEnabled(g_instakillActive ? TRUE : FALSE);
    BunnyHop_SetEnabled(g_bhopActive ? TRUE : FALSE);
    BunnyHop_SetSpeed((float)g_bhopSpeed);
    BunnyHop_SetVertical((float)g_bhopVertical);
    HSpeed_SetEnabled(g_hsActive ? TRUE : FALSE);
    if (g_hsActive) HSpeed_SetMultiplier((float)g_hsMult);
    MSpeed_SetEnabled(g_msActive ? TRUE : FALSE);
    if (g_msActive) MSpeed_SetValue(5.0f);
    InfiniteAmmo_SetEnabled(g_ammoActive ? TRUE : FALSE);
    PlayerCloner_SetEnabled(g_clonerActive ? TRUE : FALSE);
    InteractAura_SetEnabled(g_itarActive ? TRUE : FALSE);
    Revive_SetEnabled(g_reviveActive ? TRUE : FALSE);
#ifndef SERAPH_EXCLUDE_ESP
    EspOverlay_SetMaster(g_espMasterActive ? TRUE : FALSE);
    EspOverlay_SetDrawBoxes(g_espActive ? TRUE : FALSE);
    if (IsEspOverlayNeeded()) EspOverlay_Start();
    else EspOverlay_Stop();
    
    Aimbot_SetEnabled(g_aimbotActive ? TRUE : FALSE);
    Aimbot_SetShowFov(g_aimbotShowFov ? TRUE : FALSE);
    Aimbot_SetTargetHead(g_aimbotHeadTarget ? TRUE : FALSE);
    Aimbot_SetSwitchDelay(g_aimbotSwitchDelayActive ? g_aimbotSwitchDelayVal * 0.1f : 0.0f);
    Aimbot_SetSmooth(g_aimbotSmooth);
    Aimbot_SetFovSize(g_aimbotFovSize);
    if (g_aimbotActive) Aimbot_SetKey(g_aimbotHotkey);
    Aimbot_SetMemoryAim(g_aimbotMemoryAim ? TRUE : FALSE);
    EspOverlay_SetHideAllies(g_espTeamCheck ? TRUE : FALSE);
    Aimbot_SetTeamCheck(g_aimbotTeamCheck ? TRUE : FALSE);
#endif
    EspOverlay_SetDrawSkeleton(g_skeletonActive ? TRUE : FALSE);
    EspOverlay_SetDrawHealth(g_espDrawHealth ? TRUE : FALSE);
    EspOverlay_SetDrawShield(g_espDrawShield ? TRUE : FALSE);
    EspOverlay_SetDrawDistance(g_espDrawDistance ? TRUE : FALSE);
    EspOverlay_SetDrawName(g_espDrawName ? TRUE : FALSE);
    if (g_rofActive) RapidFire_SetMultiplier(1.0f - (float)(g_rofMult - 1) * (0.7f / 9.0f));
    RapidFire_SetEnabled(g_rofActive);
    SilentAim_SetEnabled(g_silentActive ? TRUE : FALSE);
    if (g_silentActive) SilentAim_SetMagnetism((float)g_silentValue);
    NoRecoil_SetEnabled(g_noRecoilActive ? TRUE : FALSE);
    
    Guardian_SetEnabled(g_guardianActive ? TRUE : FALSE);
    if (g_guardianActive) Guardian_SetValue(g_guardianValue);
    else Guardian_SetValue(100);
    
    if (!g_ncActive) NameChanger_SetEnabled(FALSE);
    else {
        char _u8[32] = {};
        WideCharToMultiByte(CP_UTF8, 0, g_ncNameBuf, -1, _u8, 32, NULL, NULL);
        NameChanger_SetName(_u8[0] ? _u8 : nullptr);
        NameChanger_SetEnabled(TRUE);
    }
    
    for (int pi = 0; pi < Patch_Count(); pi++) {
        bool shouldBeApplied = g_patchActive[pi];
        bool isApplied = Patch_IsApplied(pi);
        if (shouldBeApplied != isApplied) {
            if (shouldBeApplied && strcmp(Patch_GetName(pi), "Infinite Stacks") == 0) {
                UINT8 nb[] = { 0xC6, 0x47, 0x30, (UINT8)g_stackCount, 0x90, 0x90, 0x90 };
                Patch_SetBytes(pi, nb, 7);
            }
            Patch_Toggle(pi);
        }
    }
}

static void SaveConfigJson(const std::string& name) {
    std::wstring dir = GetConfigDir();
    if (dir.empty()) return;
    
    std::wstring path = dir + L"\\" + std::wstring(name.begin(), name.end()) + L".json";
    
    nlohmann::json j;
    
    j["hotkeys"]["menu"] = g_menuHotkey;
    j["hotkeys"]["fly"] = g_flyHotkey;
    j["hotkeys"]["flyDir"] = g_flyDirHotkey;
    j["hotkeys"]["gs"] = g_gsHotkey;
    j["hotkeys"]["aimbot"] = g_aimbotHotkey;
    j["hotkeys"]["aimbotTargetHead"] = g_aimbotTargetHeadHotkey;
    j["hotkeys"]["suicide"] = g_suicideHotkey;
#ifdef SERAPH_DMA_BUILD
    j["hotkeys"]["fuser"] = g_fuserHotkey;
    {
        SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
        j["kmbox"]["device_type"] = km->device_type;
        j["kmbox"]["hw_aim"] = km->hw_aim != 0;
        j["kmbox"]["auto_connect"] = km->auto_connect != 0;
        j["kmbox"]["ip"] = km->ip;
        j["kmbox"]["port"] = km->port;
        j["kmbox"]["uuid"] = km->uuid;
        j["kmbox"]["com_port"] = km->com_port;
        j["kmbox"]["baud"] = km->baud_str;
        j["settings"]["fuserActive"] = g_fuserActive;
    }
#endif
    
    j["settings"]["streamProof"] = g_streamProof;
    j["settings"]["espActive"] = g_espActive;
    j["settings"]["espTeamCheck"] = g_espTeamCheck;
    j["settings"]["aimbotActive"] = g_aimbotActive;
    j["settings"]["aimbotSmooth"] = g_aimbotSmooth;
    j["settings"]["aimbotShowFov"] = g_aimbotShowFov;
    j["settings"]["aimbotFovSize"] = g_aimbotFovSize;
    j["settings"]["aimbotHeadTarget"] = g_aimbotHeadTarget;
    j["settings"]["aimbotSwitchDelayActive"] = g_aimbotSwitchDelayActive;
    j["settings"]["aimbotSwitchDelayVal"] = g_aimbotSwitchDelayVal;
    j["settings"]["aimbotTeamCheck"] = g_aimbotTeamCheck;
    j["settings"]["skeletonActive"] = g_skeletonActive;
    j["settings"]["espDrawHealth"] = g_espDrawHealth;
    j["settings"]["espDrawShield"] = g_espDrawShield;
    j["settings"]["espDrawDistance"] = g_espDrawDistance;
    j["settings"]["espDrawName"] = g_espDrawName;
    j["settings"]["aimbotMemoryAim"] = g_aimbotMemoryAim;
#ifdef SERAPH_DMA_BUILD
    j["settings"]["aimbotVisCheck"] = g_aimbotVisCheck;
#endif
    
    j["settings"]["flyActive"] = false;
    j["settings"]["flySpeed"] = g_flySpeed;
    j["settings"]["flyDirActive"] = false;
    j["settings"]["flyDirSpeed"] = g_flyDirSpeed;
    j["settings"]["bhopActive"] = g_bhopActive;
    j["settings"]["bhopSpeed"] = g_bhopSpeed;
    j["settings"]["bhopVertical"] = g_bhopVertical;
    j["settings"]["msActive"] = g_msActive;
    
    j["settings"]["gsActive"] = g_gsActive;
    j["settings"]["gsSpeed"] = g_gsSpeed;
    j["settings"]["opkActive"] = g_opkActive;
    j["settings"]["opkDistance"] = g_opkDistance;
    j["settings"]["gsSlow"] = g_gsSlow;
    j["settings"]["dmgActive"] = g_dmgActive;
    j["settings"]["dmgValue"] = g_dmgValue;
    j["settings"]["immuneBossActive"] = g_immuneBossActive;
    j["settings"]["instakillActive"] = g_instakillActive;
    j["settings"]["itarActive"] = g_itarActive;
    j["settings"]["killAuraActive"] = g_killAuraActive;
    j["settings"]["killAuraValue"] = g_killAuraValue;
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
    j["settings"]["auraActive"] = g_auraActive;
    j["settings"]["auraValue"] = g_auraValue;
#endif
    j["settings"]["rofActive"] = g_rofActive;
    j["settings"]["rofMult"] = g_rofMult;
    j["settings"]["silentActive"] = g_silentActive;
    j["settings"]["silentValue"] = g_silentValue;
    j["settings"]["noRecoilActive"] = g_noRecoilActive;
    j["settings"]["ammoActive"] = g_ammoActive;
    j["settings"]["guardianActive"] = g_guardianActive;
    j["settings"]["guardianValue"] = g_guardianValue;
    j["settings"]["reviveActive"] = g_reviveActive;
    j["settings"]["clonerActive"] = g_clonerActive;
    j["settings"]["stackCount"] = g_stackCount;
    j["settings"]["ncActive"] = g_ncActive;
    
    char nameU8[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, g_ncNameBuf, -1, nameU8, 64, NULL, NULL);
    j["settings"]["ncName"] = std::string(nameU8);
    
    std::vector<bool> patches;
    for (int i = 0; i < 64; i++) {
        patches.push_back(g_patchActive[i]);
    }
    j["patches"] = patches;
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        
        wchar_t msg[128];
        swprintf_s(msg, L"Config '%hs' saved.", name.c_str());
        Overlay_AddNotification(L"Config Saved", msg);
    } else {
        Overlay_AddNotification(L"Config Error", L"Failed to write configuration file.");
    }
}

static void LoadConfigJson(const std::string& name, bool quiet = false) {
    std::wstring dir = GetConfigDir();
    if (dir.empty()) return;
    
    std::wstring path = dir + L"\\" + std::wstring(name.begin(), name.end()) + L".json";
    
    std::ifstream file(path);
    if (!file.is_open()) {
        if (!quiet) Overlay_AddNotification(L"Config Error", L"Configuration file not found.");
        return;
    }
    
    try {
        nlohmann::json j;
        file >> j;
        file.close();
        
        if (j.contains("hotkeys")) {
            auto& hk = j["hotkeys"];
            if (hk.contains("menu")) g_menuHotkey = hk["menu"];
            if (hk.contains("fly")) g_flyHotkey = hk["fly"];
            if (hk.contains("flyDir")) g_flyDirHotkey = hk["flyDir"];
            if (hk.contains("gs")) g_gsHotkey = hk["gs"];
            if (hk.contains("aimbot")) g_aimbotHotkey = hk["aimbot"];
            if (hk.contains("aimbotTargetHead")) g_aimbotTargetHeadHotkey = hk["aimbotTargetHead"];
            if (hk.contains("suicide")) g_suicideHotkey = hk["suicide"];
#ifdef SERAPH_DMA_BUILD
            if (hk.contains("fuser")) g_fuserHotkey = hk["fuser"];
#endif
        }

#ifdef SERAPH_DMA_BUILD
        if (j.contains("kmbox")) {
            SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
            auto &kmj = j["kmbox"];
            if (kmj.contains("device_type")) {
                int dt = kmj["device_type"];
                if (dt < 0) dt = 0;
                if (dt > 2) dt = 2;
                km->device_type = dt;
                SeraphKmbox_Disconnect();
            }
            if (kmj.contains("hw_aim")) km->hw_aim = kmj["hw_aim"] ? 1 : 0;
            if (kmj.contains("auto_connect")) km->auto_connect = kmj["auto_connect"] ? 1 : 0;
            if (kmj.contains("ip")) {
                std::string s = kmj["ip"];
                strncpy_s(km->ip, s.c_str(), sizeof(km->ip) - 1);
            }
            if (kmj.contains("port")) {
                std::string s = kmj["port"];
                strncpy_s(km->port, s.c_str(), sizeof(km->port) - 1);
            }
            if (kmj.contains("uuid")) {
                std::string s = kmj["uuid"];
                strncpy_s(km->uuid, s.c_str(), sizeof(km->uuid) - 1);
            }
            if (kmj.contains("com_port")) {
                std::string s = kmj["com_port"];
                strncpy_s(km->com_port, s.c_str(), sizeof(km->com_port) - 1);
            }
            if (kmj.contains("baud")) {
                std::string s = kmj["baud"];
                strncpy_s(km->baud_str, s.c_str(), sizeof(km->baud_str) - 1);
            }
            g_kmHwAim = km->hw_aim != 0;
            g_kmAutoConn = km->auto_connect != 0;
        }
#endif
        
        if (j.contains("settings")) {
            auto& s = j["settings"];
            if (s.contains("streamProof")) g_streamProof = s["streamProof"];
#ifdef SERAPH_DMA_BUILD
            if (s.contains("fuserActive")) {
                g_fuserActive = s["fuserActive"];
                SeraphFuser_SetEnabled(g_fuserActive ? TRUE : FALSE);
            }
#endif
            /* espMasterActive is not persisted — always defaults to false */
            if (s.contains("espActive")) g_espActive = s["espActive"];
            if (s.contains("espTeamCheck")) g_espTeamCheck = s["espTeamCheck"];
            if (s.contains("aimbotActive")) g_aimbotActive = s["aimbotActive"];
            if (s.contains("aimbotSmooth")) g_aimbotSmooth = s["aimbotSmooth"];
            if (s.contains("aimbotShowFov")) g_aimbotShowFov = s["aimbotShowFov"];
            if (s.contains("aimbotFovSize")) g_aimbotFovSize = s["aimbotFovSize"];
            if (s.contains("aimbotHeadTarget")) g_aimbotHeadTarget = s["aimbotHeadTarget"];
            if (s.contains("aimbotSwitchDelayActive")) g_aimbotSwitchDelayActive = s["aimbotSwitchDelayActive"];
            if (s.contains("aimbotSwitchDelayVal")) g_aimbotSwitchDelayVal = s["aimbotSwitchDelayVal"];
            if (s.contains("aimbotTeamCheck")) g_aimbotTeamCheck = s["aimbotTeamCheck"];
            if (s.contains("skeletonActive")) g_skeletonActive = s["skeletonActive"];
            if (s.contains("espDrawHealth")) g_espDrawHealth = s["espDrawHealth"];
            if (s.contains("espDrawShield")) g_espDrawShield = s["espDrawShield"];
            if (s.contains("espDrawDistance")) g_espDrawDistance = s["espDrawDistance"];
            if (s.contains("espDrawName")) g_espDrawName = s["espDrawName"];
            if (s.contains("aimbotMemoryAim")) g_aimbotMemoryAim = s["aimbotMemoryAim"];
#ifdef SERAPH_DMA_BUILD
            if (s.contains("aimbotVisCheck")) g_aimbotVisCheck = s["aimbotVisCheck"];
#endif
            
            if (s.contains("flyActive")) g_flyActive = false;
            if (s.contains("flySpeed")) g_flySpeed = s["flySpeed"];
            if (s.contains("flyDirActive")) g_flyDirActive = false;
            if (s.contains("flyDirSpeed")) g_flyDirSpeed = s["flyDirSpeed"];
            
            if (s.contains("bhopActive")) g_bhopActive = s["bhopActive"];
            if (s.contains("bhopSpeed")) g_bhopSpeed = s["bhopSpeed"];
            if (s.contains("bhopVertical")) g_bhopVertical = s["bhopVertical"];
            if (s.contains("msActive")) g_msActive = s["msActive"];

            if (s.contains("gsActive")) g_gsActive = s["gsActive"];
            if (s.contains("gsSpeed")) g_gsSpeed = s["gsSpeed"];
            if (s.contains("opkActive")) g_opkActive = s["opkActive"];
            if (s.contains("opkDistance")) g_opkDistance = s["opkDistance"];
            if (s.contains("gsSlow")) g_gsSlow = s["gsSlow"];
            if (s.contains("dmgActive")) g_dmgActive = s["dmgActive"];
            if (s.contains("dmgValue")) g_dmgValue = s["dmgValue"];
            if (s.contains("immuneBossActive")) g_immuneBossActive = s["immuneBossActive"];
            if (s.contains("instakillActive")) g_instakillActive = s["instakillActive"];
            if (s.contains("itarActive")) g_itarActive = s["itarActive"];
            if (s.contains("killAuraActive")) g_killAuraActive = s["killAuraActive"];
            if (s.contains("killAuraValue")) g_killAuraValue = s["killAuraValue"];
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
            if (s.contains("auraActive")) g_auraActive = s["auraActive"];
            if (s.contains("auraValue")) g_auraValue = s["auraValue"];
#endif
            if (s.contains("rofActive")) g_rofActive = s["rofActive"];
            if (s.contains("rofMult")) g_rofMult = s["rofMult"];
            if (s.contains("silentActive")) g_silentActive = s["silentActive"];
            if (s.contains("silentValue")) g_silentValue = s["silentValue"];
            if (s.contains("noRecoilActive")) g_noRecoilActive = s["noRecoilActive"];
            if (s.contains("ammoActive")) g_ammoActive = s["ammoActive"];
            if (s.contains("guardianActive")) g_guardianActive = s["guardianActive"];
            if (s.contains("guardianValue")) g_guardianValue = s["guardianValue"];
            if (s.contains("reviveActive")) g_reviveActive = s["reviveActive"];
            if (s.contains("clonerActive")) g_clonerActive = s["clonerActive"];
            if (s.contains("stackCount")) g_stackCount = s["stackCount"];
            if (s.contains("ncActive")) g_ncActive = s["ncActive"];
            
            if (s.contains("ncName")) {
                std::string ncNameU8 = s["ncName"];
                MultiByteToWideChar(CP_UTF8, 0, ncNameU8.c_str(), -1, g_ncNameBuf, 32);
                g_ncNameLen = (int)wcslen(g_ncNameBuf);
            }
        }
        
        if (j.contains("patches")) {
            auto& patches = j["patches"];
            for (int i = 0; i < 64 && i < (int)patches.size(); i++) {
                g_patchActive[i] = patches[i];
            }
        }
        
        ApplyLoadedSettings();
        
        wchar_t msg[128];
        swprintf_s(msg, L"Config '%hs' loaded.", name.c_str());
        Overlay_AddNotification(L"Config Loaded", msg);
        g_currentConfigName = name;
    } catch (...) {
        Overlay_AddNotification(L"Config Error", L"Failed to parse config file.");
    }
}

static void SaveConfig() {
    SaveConfigJson(g_currentConfigName);
}
static void LoadConfig() {
    LoadConfigJson(g_currentConfigName, true);
}
static void OpenSaveConfigModal() {
    g_showSaveConfigWindow = true;
    g_cfgNameBuf[0] = 0;
    g_cfgNameLen = 0;
    g_cfgNameFocused = false;
    Overlay_RebuildDevTab();
}
static void OpenLoadConfigModal() {
    g_showLoadConfigWindow = true;
    Overlay_RebuildDevTab();
}
static volatile LONG s_attachThreadActive  = 0;
static volatile LONG s_rebuildPending      = 0;
static volatile LONG s_notifAttachPending  = 0;
volatile LONG s_attachAllOk = 0;
static volatile LONG s_manualAttachPending = 0;
static volatile LONG s_featureInitPending  = 0;
static volatile LONG s_featureInitDone     = 0;  /* set to 1 once FIT has completed once       */

/* Runs all expensive AOB scans (OnAttach + D2Patches_Register) in a dedicated thread
 * so the attach itself returns immediately and the GUI becomes responsive right away. */
static DWORD WINAPI FeatureInitThread_Impl(LPVOID);
static DWORD WINAPI FeatureInitThread(LPVOID lp) {
    WriteLogFile("FeatureInitThread: ENTER");
    DWORD r = 0;
    __try { r = FeatureInitThread_Impl(lp); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        char b[80]; wsprintfA(b,"FeatureInitThread: EXCEPTION code=0x%08lX",(unsigned long)GetExceptionCode());
        WriteLogFile(b);
    }
    /* CRITICAL: Always mark attach as done, even if an OnAttach deep in FIT
     * crashed.  Otherwise the GUI stays perpetually stuck at "Attaching..."
     * because these flags were set at the tail of FIT_Impl — which never
     * ran on exception.  With this guarantee the worst-case is "partial
     * attach" (some features unavailable), which is surfaced by the
     * existing allOk gate / Overlay_AddNotification path. */
    InterlockedExchange(&s_rebuildPending,     1);
    InterlockedExchange(&s_notifAttachPending, 1);
    InterlockedExchange(&s_featureInitPending, 0);
    InterlockedExchange(&s_featureInitDone,    1);
    WriteLogFile("FeatureInitThread: EXIT");
    return r;
}
static DWORD WINAPI FeatureInitThread_Impl(LPVOID) {
    WriteLogFile("FIT: Patch_Reset");
    Patch_Reset();

    /* ── Batch AOB scan: one 512 MB pass finds all feature patterns ────────
     * Instead of N sequential 512 MB scans (~N×131 K IOCTLs) we read each
     * 4 KB page exactly once and match all patterns simultaneously (~131 K
     * IOCTLs total). Each OnAttach then consumes the cached result and skips
     * its own scan entirely.                                                */
    UINT64 cr3    = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (cr3 && d2Base) {
        /* ── Whole-module mega-batch: all AOBs in one pass ── */
    /* Delete any on-disk AOB cache left from the previous session BEFORE
     * attempting a cache-hit read.  This is a safety measure against a
     * specific failure mode: within a single Windows boot, if the game
     * receives an update and relaunches, ASLR can place the new build at
     * the EXACT SAME d2base as the old build (ASLR only re-randomises at
     * boot time).  In that case AobCache_Read() would return a "cache hit"
     * while every stored VA is wrong → patches_valid skips the live scan →
     * all D2Patches disappear from the menu, and module features like
     * GameSpeed / Guardian / Damage silently do nothing when toggled.
     *
     * Deleting upfront ensures a fresh scan on every loader launch.
     * Cost: a few extra seconds for the multi-pattern scan — acceptable
     * vs. the risk of a completely broken session.                        */
    AobCache_Delete();
    WriteLogFile("FIT: AOB cache cleared (fresh scan guaranteed)");

        /* ── Marathon Dynamic AOB Scan ── */
        WriteLogFile("FIT: Starting Marathon Dynamic AOB Scan...");
        BOOL allOk = FALSE;
        char logBuf[256];
        
        // Obfuscated AOB patterns to prevent static memory signatures in `.rdata`
        UINT8 pat_vp[] = {0x9F, 0x22, 0x4A, 0x4F, 0x5A, 0x5A, 0x5A, 0x5A, 0x9F, 0x22, 0x4A, 0x7F, 0x27, 0xC7};
        UINT8 msk_vp[] = {0xA5, 0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
        
        UINT8 pat_dt[] = {0x16, 0xD1, 0x5F, 0x5A, 0x5A, 0x5A, 0x5A, 0x12, 0xDF, 0x88, 0xB3, 0x2D, 0x70};
        UINT8 msk_dt[] = {0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
        
        UINT8 pat_pa[] = {0x12, 0xD1, 0x5F, 0x5A, 0x5A, 0x5A, 0x5A, 0x12, 0xDF, 0x9A, 0x2E, 0x5A, 0x12, 0xD7};
        UINT8 msk_pa[] = {0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0x5A, 0xA5, 0xA5};
        
        UINT8 pat_po[] = {0x12, 0xD1, 0x47, 0x5A, 0x5A, 0x5A, 0x5A, 0x55, 0xED, 0x9B, 0x1E, 0xD1, 0xAB};
        UINT8 msk_po[] = {0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};
        
        UINT8 pat_so[] = {0x16, 0xD1, 0x5F, 0x5A, 0x5A, 0x5A, 0x5A, 0x55, 0xF5, 0x8B, 0x12, 0xDB, 0x98};
        UINT8 msk_so[] = {0xA5, 0xA5, 0xA5, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};

        for (int i = 0; i < 14; i++) { pat_vp[i] ^= 0x5A; msk_vp[i] ^= 0x5A; }
        for (int i = 0; i < 13; i++) { pat_dt[i] ^= 0x5A; msk_dt[i] ^= 0x5A; }
        for (int i = 0; i < 14; i++) { pat_pa[i] ^= 0x5A; msk_pa[i] ^= 0x5A; }
        for (int i = 0; i < 13; i++) { pat_po[i] ^= 0x5A; msk_po[i] ^= 0x5A; }
        for (int i = 0; i < 13; i++) { pat_so[i] ^= 0x5A; msk_so[i] ^= 0x5A; }

        BYOVD_SCAN_ENTRY feText[5] = {
            { pat_vp, msk_vp, 14, 0, 0 },
            { pat_dt, msk_dt, 13, 0, 0 },
            { pat_pa, msk_pa, 14, 0, 0 },
            { pat_po, msk_po, 13, 0, 0 },
            { pat_so, msk_so, 13, 0, 0 }
        };

        BYOVD_LOCK();
        int foundCount = BYOVD_ScanMultiPatternText(cr3, d2Base, feText, 5);
        BYOVD_UNLOCK();

        wsprintfA(logBuf, "FIT: Multi-pattern scan completed (found %d/5 patterns)", foundCount);
        WriteLogFile(logBuf);

        BOOL ok_vp = FALSE, ok_dt = FALSE, ok_pa = FALSE, ok_po = FALSE, ok_so = FALSE;

        UINT64 va_vp = feText[0].result;
        if (va_vp) {
            INT32 disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, va_vp + 4, &disp, 4);
            BYOVD_UNLOCK();
            extern UINT64 g_RVA_VpMatrix;
            g_RVA_VpMatrix = (va_vp + 8 + disp) - d2Base;
            wsprintfA(logBuf, "FIT: ViewProjMatrix resolved dynamically to RVA +0x%I64X", g_RVA_VpMatrix);
            WriteLogFile(logBuf);
            ok_vp = TRUE;
        } else {
            WriteLogFile("FIT: ERROR: ViewProjMatrix AOB not found!");
        }

        UINT64 va_dt = feText[1].result;
        if (va_dt) {
            INT32 disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, va_dt + 3, &disp, 4);
            BYOVD_UNLOCK();
            extern UINT64 g_RVA_DatumTable;
            g_RVA_DatumTable = (va_dt + 7 + disp) - d2Base;
            wsprintfA(logBuf, "FIT: DatumTable resolved dynamically to RVA +0x%I64X", g_RVA_DatumTable);
            WriteLogFile(logBuf);
            ok_dt = TRUE;
        } else {
            WriteLogFile("FIT: ERROR: DatumTable AOB not found!");
        }

        UINT64 va_pa = feText[2].result;
        if (va_pa) {
            INT32 disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, va_pa + 3, &disp, 4);
            BYOVD_UNLOCK();
            extern UINT64 g_RVA_PlayerArray;
            g_RVA_PlayerArray = (va_pa + 7 + disp) - d2Base;
            wsprintfA(logBuf, "FIT: PlayerArray resolved dynamically to RVA +0x%I64X", g_RVA_PlayerArray);
            WriteLogFile(logBuf);
            ok_pa = TRUE;
        } else {
            WriteLogFile("FIT: ERROR: PlayerArray AOB not found!");
        }

        UINT64 va_po = feText[3].result;
        if (va_po) {
            INT32 disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, va_po + 3, &disp, 4);
            BYOVD_UNLOCK();
            extern UINT64 g_RVA_PlayerObjectArray;
            g_RVA_PlayerObjectArray = (va_po + 7 + disp) - d2Base;
            extern UINT64 g_RVA_PlayerObjectArrayDecryptRVA;
            g_RVA_PlayerObjectArrayDecryptRVA = g_RVA_PlayerObjectArray + 0x14;
            wsprintfA(logBuf, "FIT: PlayerObjectArray resolved dynamically to RVA +0x%I64X", g_RVA_PlayerObjectArray);
            WriteLogFile(logBuf);
            ok_po = TRUE;
        } else {
            WriteLogFile("FIT: ERROR: PlayerObjectArray AOB not found!");
        }

        UINT64 va_so = feText[4].result;
        if (va_so) {
            INT32 disp = 0;
            BYOVD_LOCK();
            BYOVD_ReadVA_NoCache(cr3, va_so + 3, &disp, 4);
            BYOVD_UNLOCK();
            extern UINT64 g_RVA_SObjectList;
            g_RVA_SObjectList = (va_so + 7 + disp) - d2Base;
            wsprintfA(logBuf, "FIT: SObjectList resolved dynamically to RVA +0x%I64X", g_RVA_SObjectList);
            WriteLogFile(logBuf);
            ok_so = TRUE;
        } else {
            WriteLogFile("FIT: ERROR: SObjectList AOB not found!");
        }

        if (ok_vp && ok_dt && ok_pa && ok_po && ok_so) {
            allOk = TRUE;
        }

        // Gravar offsets no arquivo "offsets.log"
        extern UINT64 g_RVA_VpMatrix;
        extern UINT64 g_RVA_DatumTable;
        extern UINT64 g_RVA_PlayerArray;
        extern UINT64 g_RVA_PlayerObjectArray;
        extern UINT64 g_RVA_SObjectList;
        
        HANDLE hLog = CreateFileA("offsets.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hLog != INVALID_HANDLE_VALUE) {
            char wBuf[512];
            int len = snprintf(wBuf, sizeof(wBuf),
                "(viewprojectionmatrix : +0x%I64X)\r\n"
                "(datumtable : +0x%I64X)\r\n"
                "(playerarray : +0x%I64X)\r\n"
                "(playerobjectarray : +0x%I64X)\r\n"
                "(sobjectlist : +0x%I64X)\r\n",
                g_RVA_VpMatrix, g_RVA_DatumTable, g_RVA_PlayerArray, g_RVA_PlayerObjectArray, g_RVA_SObjectList);
            if (len > 0) {
                DWORD written;
                WriteFile(hLog, wBuf, (DWORD)len, &written, NULL);
            }
            CloseHandle(hLog);
            WriteLogFile("FIT: Wrote offsets to offsets.log");
        }


        InterlockedExchange(&s_attachAllOk, allOk ? 1 : 0);
        WriteLogFile(allOk ? "FIT: all features ready" : "FIT: some features not ready");
    }
    // LoadConfigJson("default", true); /* disabled by default at startup */
    InterlockedExchange(&s_rebuildPending, 1);
    InterlockedExchange(&s_notifAttachPending, 1);
    InterlockedExchange(&s_featureInitPending, 0);
    InterlockedExchange(&s_featureInitDone, 1);
    return 0;
}
static DWORD WINAPI AutoAttachThread(LPVOID) {
    if (InterlockedCompareExchange(&s_attachThreadActive, 1, 0) != 0) return 0;
    for (;;) {
        /* ── Phase 1: Aguarda e anexa ────────────────── */
        while (GetDestiny2CR3() == 0) {
            /* Check if manual attach was requested from render thread */
            if (InterlockedCompareExchange(&s_manualAttachPending, 0, 1) == 1) {
                /* Manual attach: try once immediately, then kick off feature init thread */
                if (AttachToDestiny2()) {
                    if (InterlockedCompareExchange(&s_featureInitPending, 1, 0) == 0)
                        { HANDLE _hT=SeraphCreateThread(FeatureInitThread, NULL); if(_hT) SysNtClose(_hT); }
                }
                continue;
            }
            /* Poll for process at 500ms intervals until found */
            if (!Destiny2ProcessFound()) {
                SeraphSleep(200);
                continue;
            }
            /* Process found — retry AttachToDestiny2 at 150ms until base resolves.
             * During D2 startup the PEB may not be mapped yet. */
            int retries = 0;
            while (GetDestiny2CR3() == 0 && retries < 10) {
                if (AttachToDestiny2()) {
                    /* DKOM: unlink EPROCESS + ETHREADs from kernel lists now that game is attached */
                    extern void BYOVD_DkomStealth(void);
                    BYOVD_DkomStealth();
                    /* Kick off all expensive AOB scans in a background thread so
                     * the GUI becomes responsive immediately after attach. */
                    if (InterlockedCompareExchange(&s_featureInitPending, 1, 0) == 0)
                        { HANDLE _hT=SeraphCreateThread(FeatureInitThread, NULL); if(_hT) SysNtClose(_hT); }
                    break;
                }
                /* Jogo ainda carregando — espera 150ms e tenta novamente */
                SeraphSleep(150);
                retries++;
            }
        }
        /* ── Phase 2: Monitora processo ativo ──────────── */
        /* Aguarda FeatureInitThread antes do polling de detach. */
        while (s_featureInitPending) SeraphSleep(50);
        /* Poll 500ms: VMMDLL PID lookup (sem Attach) + invalidate cache no miss. */
        int missCount = 0;
        while (GetDestiny2CR3() != 0) {
            InterlockedExchange(&s_manualAttachPending, 0);
            SeraphSleep(500);
            if (!Destiny2ProcessFound()) {
                missCount++;
                { char _mb[80]; wsprintfA(_mb, "AutoAttach: D2 miss #%d/6", missCount); WriteLogFile(_mb); }
                if (missCount < 6) continue; /* ~3s de misses antes de detach */
                /* 6 misses consecutivos (≤3s) — jogo fechou */
                WriteLogFile("AutoAttach: 6 misses — invalidate, aguardando re-launch do Marathon");
                while (s_featureInitPending) SeraphSleep(50);
                Attach_Invalidate();
                InterlockedExchange(&s_featureInitDone, 0);
                InterlockedExchange(&s_featureInitPending, 0);
                missCount = 0;
                /* Marathon: NÃO fecha o menu — o overlay é independente do jogo.
                 * Volta ao Phase 1 e aguarda o Marathon.exe ser relançado. */
                break; /* Sai do while(CR3!=0) para voltar ao Phase 1 */
            }
            missCount = 0;
        }
        /* volta ao Phase 1 para re-attach na próxima instância */
    }
    /* nunca chega aqui */
    s_attachThreadActive = 0;
    return 0;
}

void InitUI(){
GetClientRect(g_hW,&g_sR);
int W=g_sR.right,H=g_sR.bottom;
int sW=220,hH=50,fH=0;
int cX=sW+40,cE=W-20;
// Sidebar nav — ESP tab is LAST so hiding it via SERAPH_EXCLUDE_ESP doesn't leave a visual gap between MISC/SETTING/DEV.
// aT mapping stable: PLAYER=aT4, MOVEMENT=aT5, WEAPONS=aT6, MISC=aT1, SETTING=aT2, DEV=aT3, TELEPORTS=aT9, ESP=aT7, AIMBOT=aT8.
g_tE[0].push_back({UE::TabButton,{12,195,sW-12,227},0,0,0,0,L"SETTINGS"});
g_tE[0].push_back({UE::TabButton,{12,235,sW-12,267},0,0,0,0,L"ESP"});
g_tE[0].push_back({UE::TabButton,{12,275,sW-12,307},0,0,0,0,L"AIMBOT"});
g_tE[0].push_back({UE::TabButton,{12,315,sW-12,347},0,0,0,0,L"DEV"});
// MISC content (empty)
// SETTING content is now built in Overlay_RebuildDevTab() so it picks up
// current client rect on every rebuild (avoids stale W/H after resize).
g_aT=7; // Start on ESP tab
}
static inline ID2D1SolidColorBrush* SB(float r, float g, float b, float a) {
    if (!g_scratchBr || !g_rT) return NULL;
    g_scratchBr->SetColor(D2D1::ColorF(r, g, b, a));
    return g_scratchBr;
}
static void DR(float x1,float y1,float x2,float y2,float r,float g,float b,float a){
    if(!g_rT)return;
    ID2D1SolidColorBrush* br = SB(r,g,b,a);
    if(br) g_rT->FillRectangle(D2D1::RectF(x1,y1,x2,y2),br);
}

/* RenderNotifications — definido em d2d_engine.cpp (Notif struct + g_notifs lá) */
extern void RenderNotifications(void);
#if 0  /* versão antiga local — desativada após migração para d2d_engine.cpp */
static void RenderNotifications_OLD(){
    if(!g_rT||!g_mTF||!g_sTF||g_notifs.empty())return;
    /* Delta time */
    DWORD now=GetTickCount();
    float dt=(g_notifLastTick==0)?0.016f:((float)(now-g_notifLastTick)/1000.f);
    if(dt>0.1f)dt=0.1f;
    g_notifLastTick=now;
    /* Compute target Y for each notification (stack grows downward, newest at bottom) */
    /* After removal, survivors slide up smoothly */
    float yT=NOTIF_TOP;
    for(int i=0;i<(int)g_notifs.size();i++){
        g_notifs[i].elapsed+=dt;
        /* Smooth Y animation */
        float target=yT;
        float speed=10.f;
        g_notifs[i].yAnim+=(target-g_notifs[i].yAnim)*dt*speed;
        /* Alpha: fade-in at start, fade-out near end */
        float e=g_notifs[i].elapsed;
        float dur=g_notifs[i].duration>0.f?g_notifs[i].duration:NOTIF_DUR;
        float a=1.f;
        if(e<NOTIF_FADE)a=e/NOTIF_FADE;
        else if(e>dur-NOTIF_FADE)a=(dur-e)/NOTIF_FADE;
        if(a<0.f)a=0.f;if(a>1.f)a=1.f;
        g_notifs[i].alpha=a;
        yT+=NOTIF_H+NOTIF_PAD;
    }
    /* Remove expired */
    for(int i=(int)g_notifs.size()-1;i>=0;i--){
        float dur=g_notifs[i].duration>0.f?g_notifs[i].duration:NOTIF_DUR;
        if(g_notifs[i].elapsed>=dur)g_notifs.erase(g_notifs.begin()+i);
    }
    /* Draw each */
    for(auto&n:g_notifs){
        float x=NOTIF_X, y=n.yAnim;
        float x2=x+NOTIF_W, y2=y+NOTIF_H;
        float a=n.alpha;
        /* Progress fraction: 0→1 over lifetime (bar fills left→right) */
        float dur=n.duration>0.f?n.duration:NOTIF_DUR;
        float prog=n.elapsed/dur;
        if(prog>1.f)prog=1.f;
        /* Background: very dark navy, matching menu bg */
        {ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(0.04f,0.07f,0.11f,0.94f*a),&br);
        if(br){auto rr=D2D1::RoundedRect(D2D1::RectF(x,y,x2,y2),8,8);g_rT->FillRoundedRectangle(rr,br);br->Release();}}
        /* Border: subtle cyan, matching menu accent */
        {ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.898f,1.0f,0.28f*a),&br);
        if(br){auto rr=D2D1::RoundedRect(D2D1::RectF(x,y,x2,y2),8,8);g_rT->DrawRoundedRectangle(rr,br,1.0f);br->Release();}}
        /* Left accent bar: bright cyan 3px */
        {ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(0.0f,0.898f,1.0f,0.85f*a),&br);
        if(br){g_rT->DrawLine({x+1.5f,y+8},{x+1.5f,y2-8},br,2.5f);br->Release();}}
        /* Header text */
        {ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(1.f,1.f,1.f,a),&br);
        if(br){
            D2D1_RECT_F r={x+12,y+10,x2-6,y+32};
            g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            g_rT->DrawText(n.hdr,(UINT32)wcslen(n.hdr),g_mTF,r,br);
            g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            br->Release();}}
        /* Body text */
        {ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(0.7f,0.78f,0.85f,0.9f*a),&br);
        if(br){
            D2D1_RECT_F r={x+12,y+32,x2-6,y+52};
            g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            g_rT->DrawText(n.bdy,(UINT32)wcslen(n.bdy),g_sTF,r,br);
            g_sTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
            br->Release();}}
        /* Progress bar track */
        {float bx=x+8,by=y2-9,bx2=x2-8,by2=y2-4;
        ID2D1SolidColorBrush*br=NULL;
        g_rT->CreateSolidColorBrush(D2D1::ColorF(1.f,1.f,1.f,0.08f*a),&br);
        if(br){auto rr=D2D1::RoundedRect(D2D1::RectF(bx,by,bx2,by2),3,3);g_rT->FillRoundedRectangle(rr,br);br->Release();}
        /* Progress bar fill: green */
        float fillX2=bx+(bx2-bx)*prog;
        if(fillX2>bx){
            g_rT->CreateSolidColorBrush(D2D1::ColorF(0.1f,0.85f,0.35f,0.9f*a),&br);
            if(br){auto rr=D2D1::RoundedRect(D2D1::RectF(bx,by,fillX2,by2),3,3);g_rT->FillRoundedRectangle(rr,br);br->Release();}
        }}
    }
}
#endif  /* fim do #if 0 — RenderNotifications_OLD desativada */

static void DT_C(const wchar_t* t,float x1,float y1,float x2,float y2,float r,float g,float b,float a,IDWriteTextFormat* f=0){
    if(!g_rT)return;
    if(!f)f=g_tF;
    ID2D1SolidColorBrush* br = SB(r,g,b,a);
    if(br){
        D2D1_RECT_F rect={x1,y1,x2,y2};
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        f->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rect,br);
        f->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        f->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
    }
}
static void DT(const wchar_t* t,float x,float y,float r,float g,float b,float a,IDWriteTextFormat* f=0){
    if(!g_rT)return;
    if(!f)f=g_tF;
    ID2D1SolidColorBrush* br = SB(r,g,b,a);
    if(br){
        D2D1_RECT_F rect={x,y,x+400,y+30};
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rect,br);
    }
}
/* DTail: draws text so the tail (end) is always visible when it overflows clipX1..clipX2 */
static void DTail(const wchar_t* t,float clipX1,float clipX2,float y,float r,float g,float b,float a,IDWriteTextFormat* f=0){
    if(!g_rT||!g_dF||!t||!t[0])return;
    if(!f)f=g_mTF;
    float maxW=clipX2-clipX1-4.f;
    float drawX=clipX1+2.f;
    IDWriteTextLayout* lay=NULL;
    if(SUCCEEDED(g_dF->CreateTextLayout(t,(UINT32)wcslen(t),f,4000.f,30.f,&lay))){
        DWRITE_TEXT_METRICS m={};lay->GetMetrics(&m);
        if(m.width>maxW) drawX=clipX2-m.width-6.f;
        lay->Release();
    }
    /* Use clipX2+20 as rect right so the tail always falls inside the layout rect,
       regardless of how negative drawX is. The PushAxisAlignedClip handles screen clipping. */
    if(!g_rT)return;
    ID2D1SolidColorBrush* br = SB(r,g,b,a);
    if(br){
        D2D1_RECT_F rect={drawX,y,clipX2+20.f,y+30.f};
        if(!f)f=g_mTF;
        g_rT->DrawText(t,(UINT32)wcslen(t),f,rect,br);
    }
}

static int ScanTpConfigsHelper(WCHAR s_tpConfigs[][64], int maxCount) {
    int count = 0;
    WCHAR dir[MAX_PATH];
    dir[0] = 0;
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, dir))) {
        wcscat_s(dir, SX(k_tp_configs_path, 18));
        std::wstring tpDir = dir;
        try {
            if (std::filesystem::exists(tpDir) && std::filesystem::is_directory(tpDir)) {
                for (const auto& entry : std::filesystem::directory_iterator(tpDir)) {
                    if (entry.is_regular_file() && entry.path().extension() == L".tp") {
                        if (count < maxCount) {
                            std::wstring stem = entry.path().stem().wstring();
                            wcsncpy_s(s_tpConfigs[count], stem.c_str(), 63);
                            s_tpConfigs[count][63] = 0;
                            count++;
                        } else {
                            break;
                        }
                    }
                }
            }
        } catch (...) {}
    }
    return count;
}

static bool g_lDPrev=false;
static bool g_rDPrev=false;
static void CM(){
if(!g_mV){g_lDPrev=false;g_rDPrev=false;return;}
bool clicked=g_lD&&!g_lDPrev; g_lDPrev=g_lD;
bool clickedRight=g_rD&&!g_rDPrev; g_rDPrev=g_rD;

/* Feature 2: Defocus TP name input when clicking outside the tp_name field */
if (g_tpNameFocused && (clicked || clickedRight)) {
    bool overTpInput = false;
    if (g_aT == 9) {
        for (auto& e : g_tE[9]) {
            if (e.t == UE::TextInput && e.txt == L"tp_name" &&
                g_mX >= e.r.left && g_mX <= e.r.right && g_mY >= e.r.top && g_mY <= e.r.bottom) {
                overTpInput = true;
                break;
            }
        }
    }
    if (!overTpInput) Overlay_TextInputDefocus();
}
#ifdef SERAPH_DMA_BUILD
if (g_showKmBoxSetup) {
    if (clicked) {
        if (g_mX >= g_kmCloseR.left && g_mX <= g_kmCloseR.right && g_mY >= g_kmCloseR.top && g_mY <= g_kmCloseR.bottom) {
            Overlay_TextInputDefocus();
            KmBox_SaveUiBuffers();
            g_showKmBoxSetup = false;
            Overlay_SaveConfig();
            Overlay_RebuildDevTab();
            return;
        }
        bool hitInput = false;
        SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
        if (km->device_type == SERAPH_KMBOX_NET) {
            if (g_mX >= g_kmIpR.left && g_mX <= g_kmIpR.right && g_mY >= g_kmIpR.top && g_mY <= g_kmIpR.bottom) {
                Overlay_TextInputDefocus();
                wcscpy_s(g_kmFocusTag, L"km_ip");
                hitInput = true;
            }
            else if (g_mX >= g_kmPortR.left && g_mX <= g_kmPortR.right && g_mY >= g_kmPortR.top && g_mY <= g_kmPortR.bottom) {
                Overlay_TextInputDefocus();
                wcscpy_s(g_kmFocusTag, L"km_port");
                hitInput = true;
            }
            else if (g_mX >= g_kmUuidR.left && g_mX <= g_kmUuidR.right && g_mY >= g_kmUuidR.top && g_mY <= g_kmUuidR.bottom) {
                Overlay_TextInputDefocus();
                wcscpy_s(g_kmFocusTag, L"km_uuid");
                hitInput = true;
            }
        } else if (km->device_type == SERAPH_KMBOX_BPLUS) {
            if (g_mX >= g_kmComR.left && g_mX <= g_kmComR.right && g_mY >= g_kmComR.top && g_mY <= g_kmComR.bottom) {
                Overlay_TextInputDefocus();
                wcscpy_s(g_kmFocusTag, L"km_com");
                hitInput = true;
            }
            else if (g_mX >= g_kmBaudR.left && g_mX <= g_kmBaudR.right && g_mY >= g_kmBaudR.top && g_mY <= g_kmBaudR.bottom) {
                Overlay_TextInputDefocus();
                wcscpy_s(g_kmFocusTag, L"km_baud");
                hitInput = true;
            }
        }
        if (!hitInput) {
            Overlay_TextInputDefocus();
        }
        if (g_mX >= g_kmDevR.left && g_mX <= g_kmDevR.right && g_mY >= g_kmDevR.top && g_mY <= g_kmDevR.bottom) {
            km->device_type = (km->device_type + 1) % 3;
            SeraphKmbox_Disconnect();
            Overlay_RebuildDevTab();
            return;
        }
        if (km->device_type != SERAPH_KMBOX_OFF) {
            if (g_mX >= g_kmConnR.left && g_mX <= g_kmConnR.right && g_mY >= g_kmConnR.top && g_mY <= g_kmConnR.bottom) {
                KmBox_SaveUiBuffers();
                SeraphKmbox_GetSettings()->hw_aim = g_kmHwAim ? 1 : 0;
                SeraphKmbox_GetSettings()->auto_connect = g_kmAutoConn ? 1 : 0;
                SeraphKmbox_Connect();
                Overlay_RebuildDevTab(); /* refresh Settings tab status label */
                return;
            }
            if (g_mX >= g_kmDiscR.left && g_mX <= g_kmDiscR.right && g_mY >= g_kmDiscR.top && g_mY <= g_kmDiscR.bottom) {
                SeraphKmbox_Disconnect();
                return;
            }
        }
    }
    return;
}
#endif
if (g_showTpConfigModal) {
    if (clicked) {
        if (g_tpConfigModalMode == 1) {
            /* Load modal: check close button */
            if (g_mX >= g_tpCloseR.left && g_mX <= g_tpCloseR.right && g_mY >= g_tpCloseR.top && g_mY <= g_tpCloseR.bottom) {
                g_showTpConfigModal = false;
                Overlay_TextInputDefocus();
                Overlay_RebuildDevTab();
                return;
            }
            /* Check click outside modal to close */
            if (g_mX < g_tpModalR.left || g_mX > g_tpModalR.right || g_mY < g_tpModalR.top || g_mY > g_tpModalR.bottom) {
                g_showTpConfigModal = false;
                Overlay_TextInputDefocus();
                Overlay_RebuildDevTab();
                return;
            }
            /* Load modal: handle config list item clicks directly */
            {
                WCHAR localTpConfigs[16][64] = {};
                int tpConfigsCount = ScanTpConfigsHelper(localTpConfigs, 16);
                
                float scrW = (float)g_sR.right;
                float scrH = (float)g_sR.bottom;
                float mW = 340.0f;
                float mX = (scrW - mW) * 0.5f;
                float mY = (scrH - 280.0f) * 0.5f;
                float listY = mY + 50;
                float itemH = 28.0f;
                int shown = 0;
                for (int i = 0; i < tpConfigsCount; i++) {
                    if (shown >= 6) break;
                    float iy = listY + shown * (itemH + 6.0f);
                    float bx = mX + 20;
                    float bw = mW - 40;
                    if (g_mX >= bx && g_mX <= bx + bw && g_mY >= iy && g_mY <= iy + itemH) {
                        char cfgName[64];
                        size_t converted = 0;
                        wcstombs_s(&converted, cfgName, sizeof(cfgName), localTpConfigs[i], _TRUNCATE);
                        TP_LoadConfig(cfgName);
                        g_showTpConfigModal = false;
                        Overlay_TextInputDefocus();
                        Overlay_RebuildDevTab();
                        Overlay_AddNotification(L"TP Config", L"TP slots loaded.");
                        return;
                    }
                    shown++;
                }
            }
            /* Swallow other clicks inside load modal */
            Overlay_TextInputDefocus();
            return;
        } else if (g_tpConfigModalMode == 2) {
            /* Save modal: check close/outside */
            if (g_mX >= g_tpCloseR.left && g_mX <= g_tpCloseR.right && g_mY >= g_tpCloseR.top && g_mY <= g_tpCloseR.bottom) {
                g_showTpConfigModal = false;
                Overlay_TextInputDefocus();
                Overlay_RebuildDevTab();
                return;
            }
            /* Check save button */
            if (g_mX >= g_tpSaveR.left && g_mX <= g_tpSaveR.right && g_mY >= g_tpSaveR.top && g_mY <= g_tpSaveR.bottom) {
                std::wstring wName = g_tpCfgNameBuf[0] ? g_tpCfgNameBuf : L"default";
                std::string cfgName(wName.begin(), wName.end());
                TP_SaveConfig(cfgName.c_str());
                g_showTpConfigModal = false;
                Overlay_TextInputDefocus();
                Overlay_RebuildDevTab();
                Overlay_AddNotification(L"TP Config", L"TP slots saved.");
                return;
            }
            /* Check click on name input */
            if (g_mX >= g_tpInputR.left && g_mX <= g_tpInputR.right && g_mY >= g_tpInputR.top && g_mY <= g_tpInputR.bottom) {
                Overlay_TextInputDefocus();
                g_tpCfgNameFocused = true;
                Overlay_RebuildDevTab();
                return;
            }
            /* Check click outside modal to close */
            /* Swallow other clicks inside save modal */
            Overlay_TextInputDefocus();
            return;
        }
    }
    /* Swallow all other interactions when teleport config modal is open */
    return;
}
if(clicked){
    g_numFocus=nullptr;g_numBufLen=0;g_numBuf[0]=0;
    if(g_ncNameFocused){
        g_ncNameFocused=false;char _u8[32]={};WideCharToMultiByte(CP_UTF8,0,g_ncNameBuf,-1,_u8,32,NULL,NULL);NameChanger_SetName(_u8[0]?_u8:nullptr);if(g_ncActive)NameChanger_SetEnabled(TRUE);
    }
    if(g_cfgNameFocused){
        g_cfgNameFocused=false;
    }
    if (g_waitingForKey || g_waitingForFlyKey || g_waitingForFlyDirKey || 
        g_waitingForGsKey || g_waitingForOpkKey || g_waitingForAimbotKey || g_waitingForAimbotTargetHeadKey || g_waitingForSuicideKey || 
        g_waitingForFuserKey || g_waitingForTpKey) 
    {
        g_waitingForKey = false;
        g_waitingForFlyKey = false;
        g_waitingForFlyDirKey = false;
        g_waitingForGsKey = false;
        g_waitingForOpkKey = false;
        g_waitingForAimbotKey = false;
        g_waitingForAimbotTargetHeadKey = false;
        g_waitingForSuicideKey = false;
        g_waitingForFuserKey = false;
        g_waitingForTpKey = false;
        Overlay_RebuildDevTab();
    }
}
if(!g_lD && !clickedRight){g_dS=false;g_dSI=-1;return;}
float W2=(float)g_sR.right;
// Close button (header X) (only on left click)
if(g_lD && g_mX>=(int)(W2-36)&&g_mX<=(int)(W2-12)&&g_mY>=10&&g_mY<=40){ReqX();return;}
// Sidebar nav (always checked, switches only on left click)
for(auto& e:g_tE[0]){
if(g_mX>=e.r.left&&g_mX<=e.r.right&&g_mY>=e.r.top&&g_mY<=e.r.bottom){
if(g_lD){
if(e.txt==L"PLAYER")g_aT=4;
else if(e.txt==L"MOVEMENT")g_aT=5;
else if(e.txt==L"WEAPONS")g_aT=6;
#ifndef SERAPH_EXCLUDE_ESP
else if(e.txt==L"TELEPORTS")g_aT=9;
else if(e.txt==L"ESP")g_aT=7;
else if(e.txt==L"AIMBOT")g_aT=8;
#endif
else if(e.txt==L"MISC")g_aT=1;
else if(e.txt==L"SETTINGS")g_aT=2;
else if(e.txt==L"DEV")g_aT=3;
/* Feature 2: Defocus TP name when leaving teleports tab */
if (g_tpNameFocused && g_aT != 9) Overlay_TextInputDefocus();

/* Rebuild active tab elements immediately on switch */
Overlay_RebuildDevTab();
}
return;}}
// Content items
for(size_t i=0;i<g_tE[g_aT].size();i++){
auto& e=g_tE[g_aT][i];
if(g_mX>=e.r.left&&g_mX<=e.r.right&&g_mY>=e.r.top&&g_mY<=e.r.bottom){
if(e.t==UE::Toggle && g_lD){DWORD _now=GetTickCount();if(_now-g_spLastToggle>350){g_spLastToggle=_now;*e.s=!*e.s;
    bool _needRebuild=false;
    if(e.s==&g_flyActive){
        Fly_SetEnabled(g_flyActive?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_flyDirActive){
        FlyDir_SetEnabled(g_flyDirActive?TRUE:FALSE);
        _needRebuild=true;
    } else if(false){ /* ammo disabled */
        (void)0;
    } else if(e.s==&g_gsActive){
        if(!g_gsActive){GameSpeed_SetSpeed(1);GameSpeed_SetSlow(1);g_gsSpeed=1;g_gsSlow=1;}
        _needRebuild=true;
    } else if(e.s==&g_opkActive){
        OPK_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_dmgActive){
        Damage_SetEnabled(*e.s);
        _needRebuild=true;
    } else if(e.s==&g_killAuraActive){
        KillAura_SetEnabled(*e.s);
        _needRebuild=true;
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
    } else if(e.s==&g_auraActive){
        Aura_SetEnabled(*e.s);
        _needRebuild=true;
#endif
    } else if(e.s==&g_immuneBossActive){
        ImmuneBoss_SetEnabled(*e.s);
        _needRebuild=true;
    } else if(e.s==&g_instakillActive){
        InstaKill_SetEnabled(*e.s);
        _needRebuild=true;
        _needRebuild=true;
    } else if(e.s==&g_bhopActive){
        BunnyHop_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_ammoActive){
        InfiniteAmmo_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_ammoBrickActive){
        AmmoBrick_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_hsActive){
        HSpeed_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_clonerActive){
        PlayerCloner_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_itarActive){
        InteractAura_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_reviveActive){
        Revive_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    } else if(e.s==&g_msActive){
        MSpeed_SetEnabled(*e.s?TRUE:FALSE);
        _needRebuild=true;
    /* } else if(e.s==&g_chamsActive){
        Chams_SetEnabled(*e.s);
        _needRebuild=true; */
#ifndef SERAPH_EXCLUDE_ESP
    } else if(e.s==&g_espTeamCheck){
        EspOverlay_SetHideAllies(*e.s?TRUE:FALSE);
    } else if(e.s==&g_espActive){
        EspOverlay_SetDrawBoxes(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
        _needRebuild=true;
    } else if(e.s==&g_espMasterActive){
        EspOverlay_SetMaster(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
        _needRebuild=true;
    } else if(e.s==&g_aimbotActive){
        Aimbot_SetEnabled(*e.s?TRUE:FALSE);
        if(*e.s){
            EspOverlay_Start(); /* idempotent — starts thread only if not already running */
        } else {
            if(!IsEspOverlayNeeded()) EspOverlay_Stop();
        }
        _needRebuild=true;
#ifdef SERAPH_DMA_BUILD
    } else if(e.s==&g_fuserActive){
        SeraphFuser_SetEnabled(g_fuserActive?TRUE:FALSE);
    } else if(e.s==&g_kmHwAim){
        SeraphKmbox_GetSettings()->hw_aim = g_kmHwAim ? 1 : 0;
    } else if(e.s==&g_kmAutoConn){
        SeraphKmbox_GetSettings()->auto_connect = g_kmAutoConn ? 1 : 0;
#endif
    } else if(e.s==&g_aimbotMemoryAim){
        Aimbot_SetMemoryAim(g_aimbotMemoryAim ? TRUE : FALSE);
    } else if(e.s==&g_aimbotTeamCheck){
        Aimbot_SetTeamCheck(*e.s?TRUE:FALSE);
    } else if(e.s==&g_aimbotShowFov){
        Aimbot_SetShowFov(*e.s?TRUE:FALSE);
    } else if(e.s==&g_aimbotHeadTarget){
        Aimbot_SetTargetHead(*e.s?TRUE:FALSE);
    } else if(e.s==&g_aimbotSwitchDelayActive){
        Aimbot_SetSwitchDelay(*e.s ? g_aimbotSwitchDelayVal * 0.1f : 0.0f);
        _needRebuild=true;
    } else if(e.s==&g_skeletonActive){
        EspOverlay_SetDrawSkeleton(*e.s?TRUE:FALSE);
        if(*e.s){ Skeleton_StartUpdateThread(); EspOverlay_Start(); }
        else   { if(!IsEspOverlayNeeded()) EspOverlay_Stop(); }
        _needRebuild=true;
    } else if(e.s==&g_espDrawHealth){
        EspOverlay_SetDrawHealth(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
    } else if(e.s==&g_espDrawShield){
        EspOverlay_SetDrawShield(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
    } else if(e.s==&g_espDrawDistance){
        EspOverlay_SetDrawDistance(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
    } else if(e.s==&g_espDrawName){
        EspOverlay_SetDrawName(*e.s?TRUE:FALSE);
        if(*e.s) EspOverlay_Start(); else if(!IsEspOverlayNeeded()) EspOverlay_Stop();
    } else if(e.s==&g_espTeamCheck){
        EspOverlay_SetHideAllies(*e.s?TRUE:FALSE);
    } else if(e.s==&g_matchmakingActive){
        if(*e.s){
            EspOverlay_Start();
        } else {
            if(!IsEspOverlayNeeded()) EspOverlay_Stop();
        }
        _needRebuild=true;
#endif  /* SERAPH_EXCLUDE_ESP */
    } else if(e.s==&g_rofActive){
        if(*e.s) RapidFire_SetMultiplier(1.0f - (float)(g_rofMult - 1) * (0.7f / 9.0f));
        RapidFire_SetEnabled(*e.s);
        _needRebuild=true;
    } else if(e.s==&g_silentActive){
        SilentAim_SetEnabled(*e.s ? TRUE : FALSE);
        if(*e.s) SilentAim_SetMagnetism((float)g_silentValue);
        _needRebuild=true;
    } else if(e.s==&g_noRecoilActive){
        NoRecoil_SetEnabled(*e.s ? TRUE : FALSE);
        _needRebuild=true;
    } else if(e.s==&g_guardianActive){
        Guardian_SetEnabled(g_guardianActive?TRUE:FALSE);
        if(!g_guardianActive){g_guardianValue=100;}
        _needRebuild=true;
    } else if(e.s==&g_ncActive){
        if(!g_ncActive) NameChanger_SetEnabled(FALSE);
        _needRebuild=true;
#ifndef NDEBUG
    } else if(e.s==&g_activityLoaderActive){
        if(g_activityLoaderActive) ActivityLoader_OnAttach();
        else ActivityLoader_OnDetach();
        _needRebuild=true;
#endif
    } else if(e.s>=&g_patchActive[0]&&e.s<=&g_patchActive[63]){
        int _pid=(int)(e.s-&g_patchActive[0]);
        if(!Patch_IsApplied(_pid)&&strcmp(Patch_GetName(_pid),"Infinite Stacks")==0){
            UINT8 nb[]={0xC6,0x47,0x30,(UINT8)g_stackCount,0x90,0x90,0x90};
            Patch_SetBytes(_pid,nb,7);
        }
        BOOL _ok=Patch_Toggle(_pid);
        *e.s=_ok?true:false;
        if(strcmp(Patch_GetName(_pid),"Sparrow Anywhere")==0){
            for(int _pi=0;_pi<Patch_Count();_pi++){
                if(strcmp(Patch_GetName(_pi),"PVP Sparrow")==0){
                    if(Patch_IsApplied(_pi)!=_ok){
                        Patch_Toggle(_pi);
                        g_patchActive[_pi]=_ok;
                    }
                    break;
                }
            }
        }
        /* No Turn Back: on enable, BYOVD-write 0.0f to [rsi+0x54] using
         * the rsi captured by the always-installed observer hook so the
         * on-screen timer disappears immediately. */
        if(_ok && _pid==NoTurnBack_GetPatchId())   NoTurnBack_TriggerOneShotZero();
        if(_ok && _pid==NoJoinAllies_GetPatchId()) NoJoinAllies_TriggerOneShotZero();
        /* Mutex: if patch was just enabled and belongs to a mutex group,
         * disable all other patches in the same group */
        if(*e.s){
            int _grp=D2Patches_GetMutexGroup(_pid);
            if(_grp>0){
                for(int _mi=0;_mi<Patch_Count();_mi++){
                    if(_mi==_pid||!g_patchActive[_mi]) continue;
                    if(D2Patches_GetMutexGroup(_mi)==_grp){
                        Patch_Toggle(_mi); /* disable it */
                        g_patchActive[_mi]=false;
                    }
                }
            }
        }
    } else{D2DEngine_TickStreamProof();}
    /* Rebuild AFTER the loop body is done — avoids iterator invalidation
     * (Overlay_RebuildDevTab clears g_tE[1] which we may still be iterating). */
    if(_needRebuild){ Overlay_RebuildDevTab(); return; }
    }}
else if(e.t==UE::TabButton&&(clicked || clickedRight)){
    if(clickedRight){
        if(g_aT==9 && e.txt.size()>2 && e.txt[0]==L'('){
            int tpSlot = _wtoi(e.txt.c_str() + 1);
            if(tpSlot >= 0 && tpSlot < TP_MAX_SLOTS){
                TP_Delete(tpSlot);
                Overlay_RebuildDevTab();
                return;
            }
        }
        return;
    }
    if (g_showLoadConfigWindow) {
        if (e.txt == L"<- Back") {
            g_showLoadConfigWindow = false;
            Overlay_RebuildDevTab();
        } else {
            std::string cfgName(e.txt.begin(), e.txt.end());
            LoadConfigJson(cfgName);
            g_showLoadConfigWindow = false;
            Overlay_RebuildDevTab();
        }
    } else if (g_showSaveConfigWindow) {
        if (e.txt == L"<- Back") {
            g_showSaveConfigWindow = false;
            Overlay_RebuildDevTab();
        } else if (e.txt == L"Save Now") {
            std::wstring wName = g_cfgNameBuf[0] ? g_cfgNameBuf : L"default";
            std::string cfgName(wName.begin(), wName.end());
            SaveConfigJson(cfgName);
            g_showSaveConfigWindow = false;
            Overlay_RebuildDevTab();
        }
    } else if(e.txt==L"Exit")ReqX();
    else if(g_aT != 9 && e.txt==L"Save Config")OpenSaveConfigModal();
    else if(g_aT != 9 && e.txt==L"Load Config")OpenLoadConfigModal();
    else if(e.txt==L"Change Key"){g_waitingForKey=true;}

    else if(e.txt==L"FlyGear"){g_waitingForFlyKey=true;g_waitingForFlyDirKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"FlyDirGear"){g_waitingForFlyDirKey=true;g_waitingForFlyKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"GsGear"){g_waitingForGsKey=true;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"OpkGear"){g_waitingForOpkKey=true;g_waitingForGsKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"AimbotGear"){g_waitingForAimbotKey=true;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForSuicideKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"TargetHeadGear"){g_waitingForAimbotTargetHeadKey=true;g_waitingForAimbotKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForSuicideKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"SuicideGear"){g_waitingForSuicideKey=true;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;Overlay_RebuildDevTab();return;}
    else if(e.txt==L"Suicide"){Suicide_Trigger();}
    else if(e.txt==L"TargetSel"){Overlay_AimbotTargetHeadToggle();}
#ifdef SERAPH_DMA_BUILD
    else if(e.txt==L"⚙ KmBox Setup" || e.txt==L"KmBox Setup"){
        KmBox_LoadUiBuffers();
        g_showKmBoxSetup = true;
        g_kmFocusTag[0] = 0;
        Overlay_RebuildDevTab();
        return;
    }
    else if(e.txt==L"Fuser Hotkey"){
        g_waitingForFuserKey=true;
        g_waitingForKey=false; g_waitingForFlyKey=false; g_waitingForFlyDirKey=false;
        g_waitingForGsKey=false; g_waitingForAimbotKey=false; g_waitingForAimbotTargetHeadKey=false; g_waitingForSuicideKey=false;
    }
#endif
    else if(e.txt==L"Suicide Hotkey"){g_waitingForSuicideKey=true;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForKey=false;}
    else if(e.txt==L"Fly Hotkey"){g_waitingForFlyKey=true;g_waitingForFlyDirKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;}
    else if(e.txt==L"Fly Dir Hotkey"){g_waitingForFlyDirKey=true;g_waitingForFlyKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;}
    else if(e.txt==L"Gs Hotkey"){g_waitingForGsKey=true;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;}
    else if(e.txt==L"Opk Hotkey"){g_waitingForOpkKey=true;g_waitingForGsKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForAimbotKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;}
    else if(e.txt==L"Aimbot Hotkey"){g_waitingForAimbotKey=true;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForAimbotTargetHeadKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;}
    else if(e.txt==L"Target Head Hotkey"){g_waitingForAimbotTargetHeadKey=true;g_waitingForAimbotKey=false;g_waitingForFlyKey=false;g_waitingForFlyDirKey=false;g_waitingForGsKey=false;g_waitingForKey=false;g_waitingForOpkKey=false;}
    else if(e.txt==L"Size Reset"){
        Guardian_Reset();
        g_guardianValue=Guardian_GetValue();
        Overlay_RebuildDevTab();
        return; /* CRITICAL: exit CM loop before iterator invalidation crashes menu */
    }
    else if(e.txt==L"Apply"){
        g_ncNameFocused=false;
        char _u8[32]={};
        WideCharToMultiByte(CP_UTF8,0,g_ncNameBuf,-1,_u8,32,NULL,NULL);
        NameChanger_SetName(_u8[0]?_u8:nullptr);
        if(g_ncActive)NameChanger_SetEnabled(TRUE);
    }
#ifndef NDEBUG
    else if(e.txt==L"Apply Activity"){
        ActivityLoader_SetActivityId(g_activityIdValue);
    }
#endif
    else if(g_aT==9 && e.txt==L"Save TP"){
        std::wstring tpName = g_tpNameBuf[0] ? g_tpNameBuf : L"TP";
        int idx = TP_SaveCurrent(tpName.c_str());
        if(idx >= 0){
            g_tpNameBuf[0] = 0;
            g_tpNameLen = 0;
            Overlay_RebuildDevTab();
        }
    }
    else if(g_aT==9 && e.txt==L"Save Configs"){
        /* Open TP Save modal */
        g_tpConfigModalMode = 2;
        g_showTpConfigModal = true;
        g_tpCfgNameBuf[0] = 0;
        g_tpCfgNameLen = 0;
        g_tpCfgNameFocused = false;
        Overlay_RebuildDevTab();
    }
    else if(g_aT==9 && e.txt==L"Load Config"){
        /* Open TP Load modal */
        g_tpConfigModalMode = 1;
        g_showTpConfigModal = true;
        g_tpCfgNameBuf[0] = 0;
        g_tpCfgNameLen = 0;
        g_tpCfgNameFocused = false;
        Overlay_RebuildDevTab();
    }
    else if(g_aT==9 && e.txt.size()>2 && e.txt[0]==L'('){
        /* Click on a TP slot: extract slot index from label "(idx) Name..." */
        int tpSlot = _wtoi(e.txt.c_str() + 1);
        if (clickedRight && tpSlot >= 0 && tpSlot < TP_MAX_SLOTS) {
            TP_Delete(tpSlot);
            Overlay_RebuildDevTab();
            return;
        }
        if (clicked && tpSlot >= 0 && tpSlot < TP_MAX_SLOTS) TP_TeleportTo(tpSlot);
    }
    else if (g_aT==9 && e.txt.size()>7 && e.txt.substr(0,7)==L"TpGear_"){
        /* TP slot gear button: enter hotkey-capture mode for that slot */
        int tpSlot = _wtoi(e.txt.c_str() + 7);
        if (tpSlot >= 0 && tpSlot < TP_MAX_SLOTS) {
            g_waitingForTpKey = true;
            g_tpWaitingSlot = tpSlot;
            g_waitingForFlyKey = false;
            g_waitingForFlyDirKey = false;
            g_waitingForGsKey = false;
            g_waitingForOpkKey = false;
            g_waitingForAimbotKey = false;
            g_waitingForSuicideKey = false;
            g_waitingForKey = false;
            Overlay_RebuildDevTab();
            return;
        }
    }
    else { (void)0; }
}
else if(e.t==UE::Slider&&g_lD){
    float _lO=(g_aT==4||g_aT==5)?55.f:(g_aT==8?70.f:45.f);
    float sx=(float)e.r.left+_lO,sw=(float)(e.r.right-e.r.left)-_lO-28.f;
    float frac=((float)g_mX-sx)/sw;
    if(frac<0.f)frac=0.f;if(frac>1.f)frac=1.f;
    *e.v=e.min+(int)(frac*(float)(e.max-e.min)+0.5f);
    /* Propagate gamespeed sliders immediately */
    if(e.v==&g_gsSpeed) GameSpeed_SetSpeed(g_gsSpeed);
    else if(e.v==&g_gsSlow) GameSpeed_SetSlow(g_gsSlow);
    else if(e.v==&g_opkDistance) OPK_SetDistance((float)g_opkDistance);
    else if(e.v==&g_dmgValue) Damage_SetMultiplier(g_dmgValue);
    else if(e.v==&g_killAuraValue) KillAura_SetMultiplier(g_killAuraValue);
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
    else if(e.v==&g_auraValue) Aura_SetMultiplier(g_auraValue);
#endif
    else if(e.v==&g_guardianValue) Guardian_SetValue(g_guardianValue);
    else if(e.v==&g_rofMult) RapidFire_SetMultiplier(1.0f - (float)(g_rofMult - 1) * (0.7f / 9.0f));
    else if(e.v==&g_silentValue) SilentAim_SetMagnetism((float)g_silentValue);
    else if(e.v==&g_hsMult) HSpeed_SetMultiplier((float)g_hsMult);
    else if(e.v==&g_aimbotSmooth) Aimbot_SetSmooth(g_aimbotSmooth);
    else if(e.v==&g_aimbotFovSize) Aimbot_SetFovSize(g_aimbotFovSize);
    else if(e.v==&g_aimbotSwitchDelayVal && g_aimbotSwitchDelayActive) Aimbot_SetSwitchDelay(g_aimbotSwitchDelayVal * 0.1f);
    else if(e.v==&g_bhopSpeed) BunnyHop_SetSpeed((float)g_bhopSpeed);
    else if(e.v==&g_bhopVertical) BunnyHop_SetVertical((float)g_bhopVertical);
    else if(e.v==&g_msValue) MSpeed_SetValue((float)g_msValue);
    break;
}
else if(e.t==UE::NumberInput&&clicked){
    g_numFocus=e.v;
    g_numBufLen=0;
    g_numBuf[0]=0;
    break;
}
else if(e.t==UE::TextInput&&clicked){
#ifdef SERAPH_DMA_BUILD
    if (g_showKmBoxSetup && !e.txt.empty()) {
        wcscpy_s(g_kmFocusTag, e.txt.c_str());
        g_ncNameFocused = false;
        g_cfgNameFocused = false;
        g_tpNameFocused = false;
        g_tpCfgNameFocused = false;
    } else
#endif
    if (g_showTpConfigModal && g_tpConfigModalMode == 2) {
        /* TP Save modal: the text input is for config name */
#ifdef SERAPH_DMA_BUILD
        g_kmFocusTag[0] = 0;
#endif
        g_tpCfgNameFocused = true;
        g_tpNameFocused = false;
        g_ncNameFocused = false;
        g_cfgNameFocused = false;
    } else if (g_showSaveConfigWindow) {
#ifdef SERAPH_DMA_BUILD
        g_kmFocusTag[0] = 0;
#endif
        g_cfgNameFocused = true;
        g_ncNameFocused = false;
        g_tpNameFocused = false;
        g_tpCfgNameFocused = false;
    } else if (g_aT == 9) {
#ifdef SERAPH_DMA_BUILD
        g_kmFocusTag[0] = 0;
#endif
        g_tpNameFocused = true;
        g_ncNameFocused = false;
        g_cfgNameFocused = false;
        g_tpCfgNameFocused = false;
    } else {
#ifdef SERAPH_DMA_BUILD
        g_kmFocusTag[0] = 0;
#endif
        g_ncNameFocused = true;
        g_cfgNameFocused = false;
        g_tpNameFocused = false;
        g_tpCfgNameFocused = false;
    }
    break;
}
break;}}}
/* DX12Overlay::Create — em d2d_engine.cpp; InitUI() chamado de lá */
extern "C" void Overlay_RebuildDevTab_Impl();
void DX12Overlay::RenderMenu(){
 D2DEngine_TickStreamProof();
#ifdef SERAPH_DMA_BUILD
  SeraphKmbox_AutoConnect();
  g_fuserActive = SeraphFuser_IsEnabled() ? true : false;
#endif
  if(g_flyActive || g_flyDirActive || g_rofActive) Fly_Tick(g_flySpeed, g_flyDirSpeed);
  BunnyHop_Tick();
  NameChanger_Tick();
  /* Ammo_Tick(); -- disabled */
  OPK_SetEnabled(g_opkActive ? TRUE : FALSE);
  OPK_SetDistance(g_opkDistance);
  OPK_Tick();
  GameSpeed_Tick();
  Damage_Tick();
  Guardian_Tick();
  Revive_Tick();
  ImmuneBoss_Tick();
  InteractAura_Tick();
#if defined(SERAPH_DMA_BUILD) || !defined(NDEBUG)
  Aura_Tick();
#endif
  if (g_waitingForAimbotKey) {
      int padVk = ControllerInput_GetAnyPressedKey();
      if (padVk > 0) Overlay_SetAimbotHotkey(padVk);
  }
  if (g_waitingForAimbotTargetHeadKey) {
      int padVk = ControllerInput_GetAnyPressedKey();
      if (padVk > 0) Overlay_SetAimbotTargetHeadHotkey(padVk);
  }
  /* Consume deferred requests from AutoAttachThread (must run on main/render thread) */
  if (InterlockedCompareExchange(&s_rebuildPending, 0, 1) == 1)
      Overlay_RebuildDevTab_Impl();
  if (InterlockedCompareExchange(&s_notifAttachPending, 0, 1) == 1) {
      if (InterlockedCompareExchange(&s_attachAllOk, 0, 0) == 1) {
          Overlay_AddNotification(SX(k_seraph_hdr,6), SX(k_cheat_init,17));
      } else {
          Overlay_AddNotification(SX(k_seraph_hdr, 6), SX(k_reattach_msg, 41));
      }
  }
if(!g_r||!g_rT)return;
__try {
g_rT->BeginDraw();
float W=(float)g_sR.right,H=(float)g_sR.bottom;
float sW=220.f,hH=50.f,fH=0.f;
// Background
g_rT->Clear(D2D1::ColorF(0.020f,0.035f,0.055f));
// NOTE: ESP overlay (W2S box) lives in its OWN dedicated layered window —
// see esp_overlay.cpp.  The menu HWND is opaque and only renders the menu
// UI; trying to host the ESP here breaks when the menu is hidden via
// ShowWindow(SW_HIDE) in the gui.c hotkey handler.
if(!g_mV){g_rT->EndDraw();return;}
    CM();
    if(g_flyActive || g_flyDirActive || g_rofActive) Fly_Tick(g_flySpeed, g_flyDirSpeed); /* post-click: handles same-frame enable */
    BunnyHop_Tick();
auto Br=[&](float r,float g,float b,float a)->ID2D1SolidColorBrush*{
ID2D1SolidColorBrush*br=NULL;g_rT->CreateSolidColorBrush(D2D1::ColorF(r,g,b,a),&br);return br;};
// ===HEADER===
DR(0,0,W,hH,0.0f,0.0f,0.0f,0.4f);
{auto*b=Br(0.0f,0.898f,1.0f,0.12f);if(b){g_rT->DrawLine({0,hH},{W,hH},b,1.f);b->Release();}}
// Top cyan accent (3px)
{auto*b=Br(0.0f,0.898f,1.0f,1.0f);if(b){g_rT->DrawLine({0,1.5f},{W,1.5f},b,3.f);b->Release();}}
// "SERAPH" title
{auto*b=Br(0.0f,0.898f,1.0f,1.0f);if(b){D2D1_RECT_F r={20,12,180,42};g_tF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_tF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);{const wchar_t* _su=SX(k_seraph_uc,6);g_rT->DrawText(_su,6,g_tF,r,b);}g_tF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);b->Release();}}
// "EARLY ACCESS" pill badge — 9pt font, compact pill right next to SERAPH
{D2D1_RECT_F br={102.f,18.f,167.f,32.f};
auto*bg=Br(0.0f,0.898f,1.0f,0.07f);if(bg){g_rT->FillRoundedRectangle(D2D1::RoundedRect(br,7,7),bg);bg->Release();}
auto*bd=Br(0.0f,0.898f,1.0f,0.22f);if(bd){g_rT->DrawRoundedRectangle(D2D1::RoundedRect(br,7,7),bd,0.7f);bd->Release();}
if(g_bTF){auto*b=Br(0.0f,0.898f,1.0f,0.60f);if(b){g_bTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_bTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);g_rT->DrawText(L"EARLY ACCESS",12,g_bTF,br,b);g_bTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);g_bTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);b->Release();}}}
// Close button
{bool hx=(g_mX>=(int)(W-36)&&g_mX<=(int)(W-12)&&g_mY>=10&&g_mY<=40);
auto*b=Br(0.0f,0.898f,1.0f,hx?1.0f:0.4f);if(b){D2D1_RECT_F r={W-36,10,W-12,40};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);g_rT->DrawText(L"X",1,g_mTF,r,b);g_mTF->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);b->Release();}}
// ===SIDEBAR===
DR(0,hH,sW,H-fH,0.0f,0.0f,0.0f,0.2f);
{auto*b=Br(0.0f,0.898f,1.0f,0.10f);if(b){g_rT->DrawLine({sW,hH},{sW,H-fH},b,1.f);b->Release();}}
// Shield logo centered in sidebar (raised, with animated glow)
{static float shieldPulse=0.f;shieldPulse+=0.025f;
float glowPulse=0.55f+0.45f*sinf(shieldPulse);
float cx=sW*0.5f,cy=110.f,sc=0.5f;
D2D1_POINT_2F oP[6]={{cx,cy-60*sc},{cx+60*sc,cy-25*sc},{cx+70*sc,cy+50*sc},{cx,cy+110*sc},{cx-70*sc,cy+50*sc},{cx-60*sc,cy-25*sc}};
D2D1_POINT_2F iP[6]={{cx,cy-45*sc},{cx+50*sc,cy-15*sc},{cx+60*sc,cy+45*sc},{cx,cy+95*sc},{cx-60*sc,cy+45*sc},{cx-50*sc,cy-15*sc}};
auto MkPG=[&](D2D1_POINT_2F*pts)->ID2D1PathGeometry*{
ID2D1PathGeometry*pg=NULL;if(FAILED(g_d2F->CreatePathGeometry(&pg)))return NULL;
ID2D1GeometrySink*sk=NULL;if(SUCCEEDED(pg->Open(&sk))){sk->BeginFigure(pts[0],D2D1_FIGURE_BEGIN_HOLLOW);for(int i2=1;i2<6;i2++)sk->AddLine(pts[i2]);sk->EndFigure(D2D1_FIGURE_END_CLOSED);sk->Close();sk->Release();}return pg;};
ID2D1PathGeometry*pgO=MkPG(oP),*pgI=MkPG(iP);
// Outer wide glow (animated breathing)
{auto*b=Br(0.0f,0.898f,1.0f,0.08f*glowPulse);if(b&&pgO){g_rT->DrawGeometry(pgO,b,28.f*sc);b->Release();}}
// Mid glow
{auto*b=Br(0.0f,0.898f,1.0f,0.14f*glowPulse);if(b&&pgO){g_rT->DrawGeometry(pgO,b,14.f*sc);b->Release();}}
// Tight glow
{auto*b=Br(0.0f,0.898f,1.0f,0.22f*glowPulse);if(b&&pgO){g_rT->DrawGeometry(pgO,b,6.f*sc);b->Release();}}
// Inner ghost
{auto*b=Br(0.0f,0.898f,1.0f,0.35f);if(b&&pgI){g_rT->DrawGeometry(pgI,b,1.5f*sc);b->Release();}}
// Solid outline
{auto*b=Br(0.0f,0.898f,1.0f,1.0f);if(b&&pgO){g_rT->DrawGeometry(pgO,b,2.5f*sc);b->Release();}}
// Shine highlight on top-left facet (sweeping shimmer)
{float shimmer=0.f+0.6f*((sinf(shieldPulse*0.7f+1.2f)+1.f)*0.5f);
auto*b=Br(1.0f,1.0f,1.0f,0.22f*shimmer);
if(b&&pgO){g_rT->DrawGeometry(pgO,b,1.2f*sc);b->Release();}}
if(pgO)pgO->Release();if(pgI)pgI->Release();}
// Nav items
for(auto& e:g_tE[0]){
bool hv=(g_mX>=e.r.left&&g_mX<=e.r.right&&g_mY>=e.r.top&&g_mY<=e.r.bottom);
bool act=(e.txt==L"PLAYER"&&g_aT==4)||(e.txt==L"MOVEMENT"&&g_aT==5)||(e.txt==L"WEAPONS"&&g_aT==6)||(e.txt==L"MISC"&&g_aT==1)||(e.txt==L"SETTINGS"&&g_aT==2)
#ifndef SERAPH_EXCLUDE_ESP
    ||(e.txt==L"TELEPORTS"&&g_aT==9)
    ||(e.txt==L"ESP"&&g_aT==7)
    ||(e.txt==L"AIMBOT"&&g_aT==8)
#endif
    ||(e.txt==L"DEV"&&g_aT==3)
    ;
if(act){
    DR(e.r.left,e.r.top,e.r.right,e.r.bottom,0.0f,0.898f,1.0f,0.10f);
    {auto*b=Br(0.0f,0.898f,1.0f,0.9f);if(b){g_rT->DrawLine({(float)e.r.left,(float)e.r.top},{(float)e.r.left,(float)e.r.bottom},b,3.f);b->Release();}}
}
else if(hv)DR(e.r.left,e.r.top,e.r.right,e.r.bottom,0.0f,0.898f,1.0f,0.03f);
float ty=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
auto*b=Br(act?0.0f:(hv?0.9f:0.6f),act?0.898f:(hv?0.9f:0.6f),act?1.0f:(hv?0.9f:0.6f),1.0f);
if(b){D2D1_RECT_F r={(float)e.r.left+15,ty,(float)e.r.right,ty+24};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(e.txt.c_str(),(UINT32)e.txt.size(),g_mTF,r,b);b->Release();}}
// ===CONTENT===
// Content title
{const wchar_t*title=L"";
if(g_aT==4)title=L"PLAYER";
else if(g_aT==5)title=L"MOVEMENT";
else if(g_aT==6)title=L"WEAPONS";
#ifndef SERAPH_EXCLUDE_ESP
else if(g_aT==9)title=L"TELEPORTS";
else if(g_aT==7)title=L"ESP";
else if(g_aT==8)title=L"AIMBOT";
#endif
else if(g_aT==1)title=L"MISC";
else if(g_aT==2)title=L"SETTINGS";
else if(g_aT==3)title=L"DEV";
auto*b=Br(0.0f,0.898f,1.0f,1.0f);if(b){D2D1_RECT_F r={sW+40,hH+20,(float)g_sR.right-20,hH+46};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(title,(UINT32)wcslen(title),g_mTF,r,b);b->Release();}}
// Title divider
{auto*b=Br(0.0f,0.898f,1.0f,0.12f);if(b){g_rT->DrawLine({sW+40,hH+50},{W-20,hH+50},b,1.f);b->Release();}}

if (g_aT == 9) {
    int firstListIdx = -1;
    int lastListIdx = -1;
    for (size_t i = 0; i < g_tE[9].size(); i++) {
        auto& e = g_tE[9][i];
        if (e.t == UE::TabButton && e.txt.size() > 2 && e.txt[0] == L'(') {
            if (firstListIdx == -1) firstListIdx = (int)i;
            lastListIdx = (int)i;
        }
    }
    if (firstListIdx != -1 && lastListIdx != -1) {
        float containerTop = (float)g_tE[9][firstListIdx].r.top;
        float containerBottom = (float)g_tE[9][lastListIdx].r.bottom;
        float containerLeft = (float)(sW + 40);
        float containerRight = (float)(W - 20);

        auto rrContainer = D2D1::RoundedRect(D2D1::RectF(containerLeft, containerTop, containerRight, containerBottom), 8, 8);
        auto* bgBrush = Br(0.03f, 0.05f, 0.08f, 1.0f);
        if (bgBrush) {
            g_rT->FillRoundedRectangle(rrContainer, bgBrush);
            bgBrush->Release();
        }
        auto* borderBrush = Br(0.08f, 0.12f, 0.16f, 1.0f);
        if (borderBrush) {
            g_rT->DrawRoundedRectangle(rrContainer, borderBrush, 1.2f);
            borderBrush->Release();
        }

        auto* sepBrush = Br(0.10f, 0.15f, 0.20f, 1.0f);
        if (sepBrush) {
            for (int idx = firstListIdx; idx < lastListIdx; idx++) {
                float sepY = (float)g_tE[9][idx].r.bottom;
                g_rT->DrawLine({containerLeft + 1, sepY}, {containerRight - 1, sepY}, sepBrush, 1.0f);
            }
            sepBrush->Release();
        }
    }
}

// Content elements
for(auto& e:g_tE[g_aT]){
bool hv=(g_mX>=e.r.left&&g_mX<=e.r.right&&g_mY>=e.r.top&&g_mY<=e.r.bottom);
if(e.t==UE::Toggle){
DR(e.r.left,e.r.top,e.r.right,e.r.bottom,1.0f,1.0f,1.0f,hv?0.04f:0.02f);
float lty=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
auto*lb=Br(0.878f,0.878f,0.878f,1.0f);if(lb){D2D1_RECT_F r={(float)e.r.left+20,lty,(float)e.r.right-70,lty+24};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(e.txt.c_str(),(UINT32)e.txt.size(),g_mTF,r,lb);lb->Release();}
// Toggle switch
float tw=44,th=22,tx2=(float)e.r.right-tw-20,ty2=e.r.top+(e.r.bottom-e.r.top)*0.5f-th*0.5f;
auto rrT=D2D1::RoundedRect(D2D1::RectF(tx2,ty2,tx2+tw,ty2+th),th/2,th/2);
if(*e.s){
    DR(e.r.left,e.r.top,e.r.right,e.r.bottom,0.0f,0.702f,0.898f,0.10f);
    auto*tb=Br(0.0f,0.702f,0.898f,0.35f);if(tb){g_rT->FillRoundedRectangle(rrT,tb);tb->Release();}
    auto*bd=Br(0.0f,0.898f,1.0f,0.90f);if(bd){g_rT->DrawRoundedRectangle(rrT,bd,1.5f);bd->Release();}
    auto*kb=Br(0.0f,0.898f,1.0f,1.0f);if(kb){g_rT->FillEllipse(D2D1::Ellipse({tx2+tw-3-8,ty2+th/2},8,8),kb);kb->Release();}
}else{
auto*tb=Br(1.0f,1.0f,1.0f,0.1f);if(tb){g_rT->FillRoundedRectangle(rrT,tb);tb->Release();}
auto*kb=Br(0.533f,0.533f,0.533f,1.0f);if(kb){g_rT->FillEllipse(D2D1::Ellipse({tx2+3+8,ty2+th/2},8,8),kb);kb->Release();}
}
}else if(e.t==UE::NumberInput){
    bool foc=(g_numFocus==e.v);
    auto rrN=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
    auto*bg=Br(0.0f,0.702f,0.898f,foc?0.18f:0.06f);if(bg){g_rT->FillRoundedRectangle(rrN,bg);bg->Release();}
    auto*bd=Br(0.0f,0.898f,1.0f,foc?0.90f:0.40f);if(bd){g_rT->DrawRoundedRectangle(rrN,bd,foc?1.5f:1.0f);bd->Release();}
    wchar_t vbuf[8]={};
    if(foc&&g_numBufLen>0){ wcsncpy_s(vbuf,8,g_numBuf,_TRUNCATE); }
    else { swprintf_s(vbuf,8,L"%d",*e.v); }
    float textX1 = (float)e.r.left, textX2 = (float)e.r.right;
    if (e.v == &g_dmgValue && *e.v == 1000 && !foc) { textX1 -= 1.5f; textX2 -= 1.5f; }
    DT_C(vbuf,textX1,(float)e.r.top,textX2,(float)e.r.bottom,0.0f,0.898f,1.0f,1.0f,g_mTF);
}else if(e.t==UE::Label){
    float lty=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
    auto*lb=Br(0.878f,0.878f,0.878f,1.0f);
    if(lb){
        D2D1_RECT_F r={(float)e.r.left,lty,(float)e.r.right,lty+24};
        g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        g_rT->DrawText(e.txt.c_str(),(UINT32)e.txt.size(),g_mTF,r,lb);
        lb->Release();
    }
}else if(e.t==UE::TextInput){
#ifdef SERAPH_DMA_BUILD
    bool focKm = g_showKmBoxSetup && g_kmFocusTag[0] &&
                 !wcscmp(e.txt.c_str(), g_kmFocusTag);
#else
    bool focKm = false;
#endif
    bool focTp = (e.txt==L"tp_name" && g_tpNameFocused);
    bool foc2 = focTp ? true : (focKm ? true : (g_showSaveConfigWindow ? g_cfgNameFocused : g_ncNameFocused));
    auto rrTI=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
    auto*bgTI=Br(0.0f,0.702f,0.898f,foc2?0.18f:0.06f);if(bgTI){g_rT->FillRoundedRectangle(rrTI,bgTI);bgTI->Release();}
    auto*bdTI=Br(0.0f,0.898f,1.0f,foc2?0.90f:0.40f);if(bdTI){g_rT->DrawRoundedRectangle(rrTI,bdTI,foc2?1.5f:1.0f);bdTI->Release();}
    /* left label */
    const wchar_t *leftLbl = nullptr;
#ifdef SERAPH_DMA_BUILD
    if (g_showKmBoxSetup) {
        if (!wcscmp(e.txt.c_str(), L"km_ip"))   leftLbl = L"IP";
        else if (!wcscmp(e.txt.c_str(), L"km_port")) leftLbl = L"Port";
        else if (!wcscmp(e.txt.c_str(), L"km_uuid")) leftLbl = L"UUID";
        else if (!wcscmp(e.txt.c_str(), L"km_com"))  leftLbl = L"COM";
        else if (!wcscmp(e.txt.c_str(), L"km_baud")) leftLbl = L"Baud";
    }
#endif
    bool tpNameField = (e.txt==L"tp_name");
    if (leftLbl || (!e.txt.empty() && !tpNameField)) {
        float ltyTI = (float)e.r.top + (float)(e.r.bottom - e.r.top) * 0.5f - 9.f;
        auto*lbTI=Br(0.6f,0.6f,0.6f,1.f);
        const wchar_t *drawLbl = leftLbl ? leftLbl : e.txt.c_str();
        UINT32 drawLen = leftLbl ? (UINT32)wcslen(leftLbl) : (UINT32)e.txt.size();
        if(lbTI){D2D1_RECT_F lrTI={(float)e.r.left+4,ltyTI,(float)e.r.left+52,ltyTI+18};
        g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        g_rT->DrawText(drawLbl, drawLen, g_sTF, lrTI, lbTI); lbTI->Release();}
    }
    float labelOff = tpNameField ? 6.0f : (e.txt.empty() ? 6.0f : 54.0f);
    float clipX1TI = (float)e.r.left + labelOff;
    float clipX2TI = (float)e.r.right - 4;
    float ltyTI2 = (float)e.r.top + (float)(e.r.bottom - e.r.top) * 0.5f - 9.f;
    const wchar_t* dispTI;
    bool isPH;
#ifdef SERAPH_DMA_BUILD
    if (focKm || (g_showKmBoxSetup && !e.txt.empty())) {
        wchar_t *kbuf = nullptr;
        int kmax = 0, *klen = nullptr;
        const wchar_t *ph = L"";
        if (KmBox_GetFieldBuf(e.txt.c_str(), &kbuf, &kmax, &klen) && kbuf && klen) {
            if (!wcscmp(e.txt.c_str(), L"km_ip"))   ph = L"192.168.2.188";
            if (!wcscmp(e.txt.c_str(), L"km_port")) ph = L"6666";
            if (!wcscmp(e.txt.c_str(), L"km_uuid")) ph = L"UUID from KmBox";
            if (!wcscmp(e.txt.c_str(), L"km_com"))  ph = L"3 or COM3";
            if (!wcscmp(e.txt.c_str(), L"km_baud")) ph = L"115200";
            dispTI = (*klen > 0 || foc2) ? kbuf : ph;
            isPH = (*klen <= 0 && !foc2);
        } else {
            dispTI = L"";
            isPH = TRUE;
        }
    } else
#endif
    if (tpNameField) {
        dispTI = (g_tpNameBuf[0]||focTp) ? g_tpNameBuf : L"TP name...";
        isPH = (!g_tpNameBuf[0]&&!focTp);
    } else if (g_showSaveConfigWindow) {
        dispTI = (g_cfgNameBuf[0]||foc2)?g_cfgNameBuf:L"default";
        isPH = (!g_cfgNameBuf[0]&&!foc2);
    } else {
        dispTI = (g_ncNameBuf[0]||foc2)?g_ncNameBuf:L"Enter name";
        isPH = (!g_ncNameBuf[0]&&!foc2);
    }
    g_rT->PushAxisAlignedClip(D2D1::RectF(clipX1TI,(float)e.r.top+2.f,clipX2TI,(float)e.r.bottom-2.f),D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    DTail(dispTI,clipX1TI,clipX2TI,ltyTI2,isPH?0.4f:0.796f,isPH?0.4f:0.835f,isPH?0.4f:0.878f,isPH?0.5f:1.0f,g_mTF);
    g_rT->PopAxisAlignedClip();
}else if(e.t==UE::Slider){
    if(g_aT==1 && (e.v==&g_gsSpeed||e.v==&g_gsSlow) && !g_gsActive) continue;
    if(g_aT==1 && e.v==&g_dmgValue && !g_dmgActive) continue;
    if(g_aT==6 && e.v==&g_silentValue && !g_silentActive) continue;
    float lOff=(g_aT==4||g_aT==5)?55.f:(g_aT==8?70.f:45.f),rOff=28.f;
    float sx=(float)e.r.left+lOff,sw=(float)(e.r.right-e.r.left)-lOff-rOff,sy=(float)(e.r.top+e.r.bottom)*0.5f;
    float frac=(e.max>e.min)?(float)(*e.v-e.min)/(float)(e.max-e.min):0.f;
    if(frac<0.f)frac=0.f;if(frac>1.f)frac=1.f;
    float kx=sx+frac*sw;
    /* Label left of bar */
    {float lty=sy-9.f;
    auto*lb=Br(0.6f,0.6f,0.6f,1.f);
    if(lb){D2D1_RECT_F lr={(float)e.r.left,lty,(float)e.r.left+lOff-4,lty+18};g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(e.txt.c_str(),(UINT32)e.txt.size(),g_sTF,lr,lb);lb->Release();}}
    auto*tb=Br(1.f,1.f,1.f,0.08f);if(tb){g_rT->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(sx,sy-3.f,sx+sw,sy+3.f),3,3),tb);tb->Release();}
    auto*fb=Br(0.f,0.898f,1.f,0.55f);if(fb){g_rT->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(sx,sy-3.f,kx,sy+3.f),3,3),fb);fb->Release();}
    auto*kb=Br(0.f,0.898f,1.f,1.f);if(kb){g_rT->FillEllipse(D2D1::Ellipse({kx,sy},7.f,7.f),kb);kb->Release();}
    auto*ob=Br(0.f,0.f,0.f,0.5f);if(ob){g_rT->DrawEllipse(D2D1::Ellipse({kx,sy},7.f,7.f),ob,1.5f);ob->Release();}
    /* Value right of bar */
    {float lty=sy-9.f;wchar_t vbuf[8]={};
    if(e.v==&g_guardianValue){swprintf_s(vbuf,8,L"%.2f",(float)*e.v/100.f);}
    else if(e.v==&g_aimbotSwitchDelayVal){swprintf_s(vbuf,8,L"%.1f",(float)*e.v*0.1f);}
    else{swprintf_s(vbuf,8,L"%d",*e.v);}
    auto*vb=Br(0.f,0.898f,1.f,1.f);if(vb){D2D1_RECT_F vr={(float)e.r.right-rOff+2,lty,(float)e.r.right+2,lty+18};g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_rT->DrawText(vbuf,(UINT32)wcslen(vbuf),g_sTF,vr,vb);vb->Release();g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);}}
}else if(e.t==UE::TabButton){
// Gear button (procedural cogwheel silhouette — thin line strokes only)
if(e.txt==L"FlyGear"||e.txt==L"FlyDirGear"||e.txt==L"GsGear"||e.txt==L"OpkGear"||e.txt==L"AimbotGear"||e.txt==L"TargetHeadGear"||e.txt==L"SuicideGear"||(e.txt.size()>7&&wcsncmp(e.txt.c_str(), L"TpGear_", 7) == 0)){
    bool open = false; (void)open;
    float cx=(float)(e.r.left+e.r.right)*0.5f;
    float cy=(float)(e.r.top+e.r.bottom)*0.5f;
    float w=(float)(e.r.right-e.r.left);
    float h=(float)(e.r.bottom-e.r.top);
    float R=(w<h?w:h)*0.5f-2.0f;
    float Router = R*0.95f;
    float Rinner = R*0.70f;
    float Rhub   = R*0.30f;
    float alpha  = open?1.0f:(hv?0.95f:0.65f);
    auto*gc=Br(0.878f,0.878f,0.878f,alpha);
    if(gc){
        const int teeth = 6;
        const int N = teeth * 4;
        const float step = 6.2831853f / (float)N;
        D2D1_POINT_2F prev = {0,0};
        for(int i=0;i<=N;i++){
            int phase = i % 4;          /* 0:inner, 1:outer, 2:outer, 3:inner */
            float r = (phase==1||phase==2) ? Router : Rinner;
            float a = (float)i * step - 1.5707963f; /* start at top */
            D2D1_POINT_2F p = { cx + cosf(a)*r, cy + sinf(a)*r };
            if(i>0) g_rT->DrawLine(prev,p,gc,1.0f);
            prev = p;
        }
        /* center hub */
        g_rT->DrawEllipse(D2D1::Ellipse({cx,cy},Rhub,Rhub),gc,1.0f);
        gc->Release();
    }
} else
// Special rendering for Change Key / Fly Hotkey / Fly Dir Hotkey buttons
if(e.txt==L"Change Key"||e.txt==L"Fly Hotkey"||e.txt==L"Fly Dir Hotkey"||e.txt==L"Gs Hotkey"||e.txt==L"Opk Hotkey"||e.txt==L"Aimbot Hotkey"||e.txt==L"Target Head Hotkey"||e.txt==L"Suicide Hotkey"||e.txt==L"Fuser Hotkey"){
    bool waiting = (e.txt==L"Change Key")?g_waitingForKey:
                   (e.txt==L"Fly Hotkey")?g_waitingForFlyKey:
                   (e.txt==L"Fly Dir Hotkey")?g_waitingForFlyDirKey:
                   (e.txt==L"Aimbot Hotkey")?g_waitingForAimbotKey:
                   (e.txt==L"Target Head Hotkey")?g_waitingForAimbotTargetHeadKey:
                   (e.txt==L"Suicide Hotkey")?g_waitingForSuicideKey:
                   (e.txt==L"Fuser Hotkey")?g_waitingForFuserKey:
                   (e.txt==L"Opk Hotkey")?g_waitingForOpkKey:g_waitingForGsKey;
    int  hk      = (e.txt==L"Change Key")?g_menuHotkey:
                   (e.txt==L"Fly Hotkey")?g_flyHotkey:
                   (e.txt==L"Fly Dir Hotkey")?g_flyDirHotkey:
                   (e.txt==L"Aimbot Hotkey")?g_aimbotHotkey:
                   (e.txt==L"Target Head Hotkey")?g_aimbotTargetHeadHotkey:
                   (e.txt==L"Suicide Hotkey")?g_suicideHotkey:
                   (e.txt==L"Fuser Hotkey")?g_fuserHotkey:
                   (e.txt==L"Opk Hotkey")?g_opkHotkey:g_gsHotkey;
    const wchar_t* lbl = (e.txt==L"Change Key")?L"Menu Key":
                          (e.txt==L"Fly Hotkey")?L"Fly Key":
                          (e.txt==L"Fly Dir Hotkey")?L"Fly Dir Key":
                          (e.txt==L"Aimbot Hotkey")?L"Aimbot Key":
                          (e.txt==L"Target Head Hotkey")?L"Target Key":
                          (e.txt==L"Suicide Hotkey")?L"Suicide Key":
                          (e.txt==L"Fuser Hotkey")?L"Fuser Key":
                          (e.txt==L"Opk Hotkey")?L"OPK Key":L"Game Speed Key";
    auto rrB=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
    // Pulsing amber when waiting, normal cyan otherwise
    static float wPulse=0.f;if(waiting)wPulse+=0.06f;else wPulse=0.f;
    float wp=waiting?(0.5f+0.5f*sinf(wPulse)):0.f;
    auto*bg=waiting?Br(1.0f,0.6f,0.0f,0.08f+0.08f*wp):Br(0.0f,0.898f,1.0f,hv?0.15f:0.05f);
    if(bg){g_rT->FillRoundedRectangle(rrB,bg);bg->Release();}
    auto*bd=waiting?Br(1.0f,0.7f,0.0f,0.5f+0.4f*wp):Br(0.0f,0.898f,1.0f,hv?0.9f:0.3f);
    if(bd){g_rT->DrawRoundedRectangle(rrB,bd,1.0f);bd->Release();}
    // Label left
    {auto*lb=Br(0.878f,0.878f,0.878f,1.0f);if(lb){D2D1_RECT_F r={(float)e.r.left+20,(float)e.r.top+8,(float)e.r.left+200,(float)e.r.bottom-8};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(lbl,(UINT32)wcslen(lbl),g_mTF,r,lb);lb->Release();}}
    // Right side: key name or prompt
    if(waiting){
        DT_C(L"Press any key...",e.r.right-200.f,(float)e.r.top,(float)e.r.right-10,(float)e.r.bottom,1.0f,0.7f,0.0f,1.0f,g_sTF);
    } else if(hk==0){
        DT_C(L"None",e.r.right-200.f,(float)e.r.top,(float)e.r.right-10,(float)e.r.bottom,0.6f,0.6f,0.6f,1.0f,g_sTF);
    } else {
        WCHAR kname[32]=L"";
        /* Friendly names for mouse buttons (GetKeyNameTextW doesn't handle them) */
        if(hk==VK_LBUTTON)      wcscpy_s(kname,32,L"Mouse L");
        else if(hk==VK_RBUTTON) wcscpy_s(kname,32,L"Mouse R");
        else if(hk==VK_MBUTTON) wcscpy_s(kname,32,L"Mouse M");
        else if(hk==VK_XBUTTON1)wcscpy_s(kname,32,L"Mouse 4");
        else if(hk==VK_XBUTTON2)wcscpy_s(kname,32,L"Mouse 5");
        else {
            GetKeyNameTextW((MapVirtualKeyW(hk,MAPVK_VK_TO_VSC)<<16),kname,32);
            if(!kname[0])wsprintfW(kname,L"VK %02X",hk);
        }
        DT_C(kname,e.r.right-200.f,(float)e.r.top,(float)e.r.right-10,(float)e.r.bottom,0.0f,0.898f,1.0f,1.0f,g_sTF);
    }
} else if(e.txt==L"Suicide"){
    /* Render like a Toggle row but without the switch — same dark bg, left text */
    DR(e.r.left,e.r.top,e.r.right,e.r.bottom,1.0f,1.0f,1.0f,hv?0.06f:0.02f);
    float lty2=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
    auto*lb2=Br(0.878f,0.878f,0.878f,1.0f);
    if(lb2){D2D1_RECT_F rr2={(float)e.r.left+20,lty2,(float)e.r.right-20,lty2+24};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(e.txt.c_str(),(UINT32)e.txt.size(),g_mTF,rr2,lb2);lb2->Release();}
} else if(e.txt==L"TargetSel"){
    /* Row: label "Target" on left, cyan pill with current value on right */
    DR(e.r.left,e.r.top,e.r.right,e.r.bottom,1.0f,1.0f,1.0f,hv?0.06f:0.02f);
    float ltyT=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
    auto*lbT=Br(0.878f,0.878f,0.878f,1.0f);
    if(lbT){D2D1_RECT_F rlT={(float)e.r.left+10,ltyT,(float)e.r.right-110,ltyT+24};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(L"Target",6,g_mTF,rlT,lbT);lbT->Release();}
    const wchar_t* valS=g_aimbotHeadTarget?L"Head":L"Body";
    D2D1_RECT_F pillR={(float)e.r.right-130,(float)e.r.top+6,(float)e.r.right-48,(float)e.r.bottom-6};
    auto rrP=D2D1::RoundedRect(pillR,8,8);
    auto*pbg=Br(0.0f,0.702f,0.898f,0.25f);if(pbg){g_rT->FillRoundedRectangle(rrP,pbg);pbg->Release();}
    auto*pbd=Br(0.0f,0.898f,1.0f,0.80f);if(pbd){g_rT->DrawRoundedRectangle(rrP,pbd,1.2f);pbd->Release();}
    auto*ptx=Br(0.0f,0.898f,1.0f,1.0f);if(ptx){g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_rT->DrawText(valS,(UINT32)wcslen(valS),g_sTF,pillR,ptx);g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);ptx->Release();}
#ifdef SERAPH_DMA_BUILD
} else if(e.txt==L"KmBoxDev"){
    DR(e.r.left,e.r.top,e.r.right,e.r.bottom,1.0f,1.0f,1.0f,hv?0.06f:0.02f);
    float ltyK=e.r.top+(e.r.bottom-e.r.top)*0.5f-9.f;
    auto*lbK=Br(0.878f,0.878f,0.878f,1.0f);
    if(lbK){D2D1_RECT_F rlK={(float)e.r.left+20,ltyK,(float)e.r.right-110,ltyK+24};g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);g_rT->DrawText(L"KmBox",5,g_mTF,rlK,lbK);lbK->Release();}
    const wchar_t* valK=L"Off";
    switch(SeraphKmbox_GetSettings()->device_type){
        case SERAPH_KMBOX_NET: valK=L"Net"; break;
        case SERAPH_KMBOX_BPLUS: valK=L"B+"; break;
        default: break;
    }
    D2D1_RECT_F pillK={(float)e.r.right-100,(float)e.r.top+6,(float)e.r.right-20,(float)e.r.bottom-6};
    auto rrK=D2D1::RoundedRect(pillK,8,8);
    auto*kbg=Br(0.0f,0.702f,0.898f,0.25f);if(kbg){g_rT->FillRoundedRectangle(rrK,kbg);kbg->Release();}
    auto*kbd=Br(0.0f,0.898f,1.0f,0.80f);if(kbd){g_rT->DrawRoundedRectangle(rrK,kbd,1.2f);kbd->Release();}
    auto*ktx=Br(0.0f,0.898f,1.0f,1.0f);if(ktx){g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_rT->DrawText(valK,(UINT32)wcslen(valK),g_sTF,pillK,ktx);g_sTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);ktx->Release();}
} else if(e.txt==L"KmBoxConn"||e.txt==L"KmBoxDisc"){
    auto rrK2=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
    auto*bgK=Br(0.0f,0.898f,1.0f,hv?0.15f:0.05f);if(bgK){g_rT->FillRoundedRectangle(rrK2,bgK);bgK->Release();}
    auto*bdK=Br(0.0f,0.898f,1.0f,hv?0.9f:0.3f);if(bdK){g_rT->DrawRoundedRectangle(rrK2,bdK,1.0f);bdK->Release();}
    const wchar_t* lblK=(e.txt==L"KmBoxConn")?L"Connect KmBox":L"Disconnect KmBox";
    auto*txK=Br(0.878f,0.878f,0.878f,1.0f);
    if(txK){g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);g_rT->DrawText(lblK,(UINT32)wcslen(lblK),g_mTF,D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),txK);g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);txK->Release();}
#endif
} else {
    if (g_aT == 9 && wcscmp(e.txt.c_str(), L"Save TP") == 0) {
        auto rrB=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
        auto*bg=Br(0.00f, 0.702f, 0.898f, hv ? 1.0f : 0.85f);
        if(bg){g_rT->FillRoundedRectangle(rrB,bg);bg->Release();}
        if (hv) {
            auto*bd=Br(0.00f, 0.898f, 1.0f, 1.0f);
            if(bd){g_rT->DrawRoundedRectangle(rrB,bd,1.5f);bd->Release();}
        }
        DT_C(L"SAVE TP", (float)e.r.left, (float)e.r.top, (float)e.r.right, (float)e.r.bottom, 0.05f, 0.05f, 0.05f, 1.0f, g_sTF);
    } else if (wcscmp(e.txt.c_str(), L"Load Config") == 0 || wcscmp(e.txt.c_str(), L"Save Config") == 0 || wcscmp(e.txt.c_str(), L"Save Configs") == 0) {
        auto rrB=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
        auto*bg=Br(0.00f, 0.702f, 0.898f, hv ? 0.08f : 0.02f);
        if(bg){g_rT->FillRoundedRectangle(rrB,bg);bg->Release();}
        auto*bd=Br(0.00f, 0.702f, 0.898f, 0.6f);
        if(bd){g_rT->DrawRoundedRectangle(rrB,bd,1.0f);bd->Release();}
        const wchar_t* displayTxt = (wcscmp(e.txt.c_str(), L"Load Config") == 0) ? L"LOAD CONFIG" : ((wcscmp(e.txt.c_str(), L"Save Config") == 0) ? L"SAVE CONFIG" : L"SAVE CONFIGS");
        DT_C(displayTxt, (float)e.r.left, (float)e.r.top, (float)e.r.right, (float)e.r.bottom, 0.00f, 0.702f, 0.898f, 1.0f, g_sTF);
    } else if (g_aT == 9 && e.txt.size() > 2 && e.txt[0] == L'(') {
        const wchar_t* txtPtr = e.txt.c_str();
        const wchar_t* closeParen = wcschr(txtPtr, L')');
        const wchar_t* openBracket = wcschr(txtPtr, L'[');
        
        wchar_t nameBuf[128] = L"";
        wchar_t coordBuf[64] = L"";
        
        if (closeParen != nullptr) {
            const wchar_t* nameStart = closeParen + 1;
            while (*nameStart == L' ') nameStart++;
            
            if (openBracket != nullptr && openBracket > nameStart) {
                const wchar_t* nameEnd = openBracket;
                while (nameEnd > nameStart && *(nameEnd - 1) == L' ') nameEnd--;
                
                size_t nameLen = nameEnd - nameStart;
                if (nameLen >= 128) nameLen = 127;
                wcsncpy_s(nameBuf, 128, nameStart, nameLen);
                nameBuf[nameLen] = L'\0';
                
                const wchar_t* coordStart = openBracket + 1;
                const wchar_t* coordEnd = wcschr(openBracket, L']');
                if (coordEnd != nullptr && coordEnd > coordStart) {
                    size_t coordLen = coordEnd - coordStart;
                    if (coordLen >= 64) coordLen = 63;
                    wcsncpy_s(coordBuf, 64, coordStart, coordLen);
                    coordBuf[coordLen] = L'\0';
                }
            } else {
                wcscpy_s(nameBuf, 128, nameStart);
            }
        } else {
            wcscpy_s(nameBuf, 128, txtPtr);
        }

        if (hv) {
            auto rrRow = D2D1::RoundedRect(D2D1::RectF((float)e.r.left + 1, (float)e.r.top + 1, (float)e.r.right - 1, (float)e.r.bottom - 1), 6, 6);
            auto* bgHov = Br(0.00f, 0.702f, 0.898f, 0.05f);
            if (bgHov) {
                g_rT->FillRoundedRectangle(rrRow, bgHov);
                bgHov->Release();
            }
        }

        float iconX = (float)e.r.left + 18.0f;
        float iconY = (float)e.r.top + (float)(e.r.bottom - e.r.top) * 0.5f;
        float starRadius = 5.0f;
        float innerRadius = 1.5f;
        auto* starBrush = Br(0.00f, 0.702f, 0.898f, 1.0f);
        if (starBrush) {
            g_rT->DrawLine({iconX, iconY - starRadius}, {iconX, iconY + starRadius}, starBrush, 1.5f);
            g_rT->DrawLine({iconX - starRadius, iconY}, {iconX + starRadius, iconY}, starBrush, 1.5f);
            auto* innerBrush = Br(0.03f, 0.05f, 0.08f, 1.0f);
            if (innerBrush) {
                g_rT->FillEllipse(D2D1::Ellipse({iconX, iconY}, innerRadius, innerRadius), innerBrush);
                innerBrush->Release();
            }
            starBrush->Release();
        }

        auto* nameBrush = Br(0.878f, 0.878f, 0.878f, 1.0f);
        if (nameBrush) {
            float textY = (float)e.r.top + ((float)(e.r.bottom - e.r.top) - 18.0f) * 0.5f;
            D2D1_RECT_F rText = {(float)e.r.left + 35.0f, textY, (float)e.r.right - 150.0f, textY + 24.0f};
            g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            g_rT->DrawText(nameBuf, (UINT32)wcslen(nameBuf), g_mTF, rText, nameBrush);
            nameBrush->Release();
        }

        auto* coordBrush = Br(0.40f, 0.45f, 0.50f, 1.0f);
        if (coordBrush) {
            float textY = (float)e.r.top + ((float)(e.r.bottom - e.r.top) - 18.0f) * 0.5f;
            D2D1_RECT_F rCoord = {(float)e.r.right - 180.0f, textY, (float)e.r.right - 18.0f, textY + 24.0f};
            g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
            g_rT->DrawText(coordBuf, (UINT32)wcslen(coordBuf), g_mTF, rCoord, coordBrush);
            g_mTF->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
            coordBrush->Release();
        }
    } else {
        auto rrB=D2D1::RoundedRect(D2D1::RectF((float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom),4,4);
        auto*bg=Br(0.0f,0.898f,1.0f,hv?0.15f:0.05f);if(bg){g_rT->FillRoundedRectangle(rrB,bg);bg->Release();}
        auto*bd=Br(0.0f,0.898f,1.0f,hv?0.9f:0.3f);if(bd){g_rT->DrawRoundedRectangle(rrB,bd,1.0f);bd->Release();}
        DT_C(e.txt.c_str(),(float)e.r.left,(float)e.r.top,(float)e.r.right,(float)e.r.bottom,0.0f,0.898f,1.0f,1.0f,g_sTF);
    }
}}}
#ifdef SERAPH_DMA_BUILD
if (g_showKmBoxSetup || g_kmBoxFade > 0.001f) {
    float dt = 1.0f / 60.0f;
    if (g_showKmBoxSetup) {
        float nextFade = g_kmBoxFade + dt * 6.0f;
        g_kmBoxFade = (nextFade > 1.0f) ? 1.0f : nextFade;
    } else {
        float nextFade = g_kmBoxFade - dt * 6.0f;
        g_kmBoxFade = (nextFade < 0.0f) ? 0.0f : nextFade;
    }
    
    // Draw backdrop overlay
    DR(0, 0, W, H, 0.0f, 0.0f, 0.0f, 0.6f * g_kmBoxFade);
    
    SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
    float mW = 400.0f;
    float mH = (km->device_type == SERAPH_KMBOX_NET) ? 340.f : ((km->device_type == SERAPH_KMBOX_BPLUS) ? 280.f : 180.f);
    float mX = (W - mW) * 0.5f;
    float mY = (H - mH) * 0.5f;
    g_kmModalR = { (LONG)mX, (LONG)mY, (LONG)(mX + mW), (LONG)(mY + mH) };
    
    auto rr = D2D1::RoundedRect(D2D1::RectF(mX, mY, mX + mW, mY + mH), 8, 8);
    auto* bg = Br(0.04f, 0.07f, 0.11f, 0.98f * g_kmBoxFade);
    if (bg) { g_rT->FillRoundedRectangle(rr, bg); bg->Release(); }
    auto* border = Br(0.0f, 0.898f, 1.0f, 0.4f * g_kmBoxFade);
    if (border) { g_rT->DrawRoundedRectangle(rr, border, 1.5f); border->Release(); }
    
    DT_C(L"KMBox Connection Setup", mX, mY + 12, mX + mW, mY + 36, 0.0f, 0.898f, 1.0f, 1.0f * g_kmBoxFade, g_mTF);
    
    float cx = mX + mW - 32;
    float cy = mY + 12;
    g_kmCloseR = { (LONG)cx, (LONG)cy, (LONG)(cx + 20), (LONG)(cy + 20) };
    bool hoverX = (g_mX >= g_kmCloseR.left && g_mX <= g_kmCloseR.right && g_mY >= g_kmCloseR.top && g_mY <= g_kmCloseR.bottom);
    DT_C(L"X", cx, cy, cx + 20, cy + 20, 0.0f, 0.898f, 1.0f, (hoverX ? 1.0f : 0.5f) * g_kmBoxFade, g_mTF);
    
    float py = mY + 55;
    
    // Row 1: Device Type
    float bx = mX + 130;
    float bw = mW - 150;
    g_kmDevR = { (LONG)bx, (LONG)py, (LONG)(bx + bw), (LONG)(py + 28) };
    bool hoverDev = (g_mX >= g_kmDevR.left && g_mX <= g_kmDevR.right && g_mY >= g_kmDevR.top && g_mY <= g_kmDevR.bottom);
    auto rrDev = D2D1::RoundedRect(D2D1::RectF(bx, py, bx + bw, py + 28), 4, 4);
    auto* bgDev = Br(0.0f, 0.702f, 0.898f, (hoverDev ? 0.18f : 0.06f) * g_kmBoxFade);
    if (bgDev) { g_rT->FillRoundedRectangle(rrDev, bgDev); bgDev->Release(); }
    auto* bdDev = Br(0.0f, 0.898f, 1.0f, (hoverDev ? 0.90f : 0.40f) * g_kmBoxFade);
    if (bdDev) { g_rT->DrawRoundedRectangle(rrDev, bdDev, hoverDev ? 1.5f : 1.0f); bdDev->Release(); }
    DT(L"Device Type:", mX + 20, py + 4, 0.7f, 0.7f, 0.7f, 1.0f * g_kmBoxFade, g_sTF);
    
    const wchar_t* devTxt = L"OFF";
    if (km->device_type == SERAPH_KMBOX_NET) devTxt = L"Network (Net)";
    else if (km->device_type == SERAPH_KMBOX_BPLUS) devTxt = L"Serial (B+)";
    DT_C(devTxt, bx, py, bx + bw, py + 28, 0.0f, 0.898f, 1.0f, 1.0f * g_kmBoxFade, g_mTF);
    
    py += 36;
    
    auto DrawModalInput = [&](const wchar_t* tag, const wchar_t* label, const wchar_t* placeholder, RECT& outRect, float& pyVar) {
        DT(label, mX + 20, pyVar + 4, 0.7f, 0.7f, 0.7f, 1.0f * g_kmBoxFade, g_sTF);
        float bxIn = mX + 130;
        float bwIn = mW - 150;
        outRect = { (LONG)bxIn, (LONG)pyVar, (LONG)(bxIn + bwIn), (LONG)(pyVar + 28) };
        bool foc = (g_kmFocusTag[0] && !wcscmp(tag, g_kmFocusTag));
        bool hover = (g_mX >= bxIn && g_mX <= bxIn + bwIn && g_mY >= pyVar && g_mY <= pyVar + 28);
        auto rrTI = D2D1::RoundedRect(D2D1::RectF(bxIn, pyVar, bxIn + bwIn, pyVar + 28), 4, 4);
        auto* bgTI = Br(0.0f, 0.702f, 0.898f, (foc ? 0.18f : (hover ? 0.12f : 0.06f)) * g_kmBoxFade);
        if (bgTI) { g_rT->FillRoundedRectangle(rrTI, bgTI); bgTI->Release(); }
        auto* bdTI = Br(0.0f, 0.898f, 1.0f, (foc ? 0.90f : 0.40f) * g_kmBoxFade);
        if (bdTI) { g_rT->DrawRoundedRectangle(rrTI, bdTI, foc ? 1.5f : 1.0f); bdTI->Release(); }
        
        wchar_t *kbuf = nullptr;
        int kmax = 0, *klen = nullptr;
        const wchar_t* dispTI = L"";
        bool isPH = true;
        if (KmBox_GetFieldBuf(tag, &kbuf, &kmax, &klen) && kbuf && klen) {
            dispTI = (*klen > 0 || foc) ? kbuf : placeholder;
            isPH = (*klen <= 0 && !foc);
        }
        float clipX1 = bxIn + 6;
        float clipX2 = bxIn + bwIn - 4;
        g_rT->PushAxisAlignedClip(D2D1::RectF(clipX1, pyVar + 2, clipX2, pyVar + 26), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        DTail(dispTI, clipX1, clipX2, pyVar + 5, isPH ? 0.4f : 0.8f, isPH ? 0.4f : 0.85f, isPH ? 0.4f : 0.9f, 1.0f * g_kmBoxFade, g_mTF);
        g_rT->PopAxisAlignedClip();
        pyVar += 36;
    };
    
    if (km->device_type == SERAPH_KMBOX_NET) {
        DrawModalInput(L"km_ip", L"IP Address:", L"192.168.2.188", g_kmIpR, py);
        DrawModalInput(L"km_port", L"Port:", L"6666", g_kmPortR, py);
        DrawModalInput(L"km_uuid", L"UUID:", L"UUID from KmBox", g_kmUuidR, py);
    } else if (km->device_type == SERAPH_KMBOX_BPLUS) {
        DrawModalInput(L"km_com", L"COM Port:", L"3 or COM3", g_kmComR, py);
        DrawModalInput(L"km_baud", L"Baud Rate:", L"115200", g_kmBaudR, py);
    } else {
        DT(L"Select Net or B+ device to configure.", mX + 20, py + 10, 0.6f, 0.6f, 0.6f, 1.0f * g_kmBoxFade, g_sTF);
        py += 40;
    }
    
    if (km->device_type != SERAPH_KMBOX_OFF) {
        auto DrawModalButton = [&](const wchar_t* text, float bxBtn, float bwBtn, RECT& outRect, float pyBtn) {
            outRect = { (LONG)bxBtn, (LONG)pyBtn, (LONG)(bxBtn + bwBtn), (LONG)(pyBtn + 28) };
            bool hover = (g_mX >= bxBtn && g_mX <= bxBtn + bwBtn && g_mY >= pyBtn && g_mY <= pyBtn + 28);
            auto rrBtn = D2D1::RoundedRect(D2D1::RectF(bxBtn, pyBtn, bxBtn + bwBtn, pyBtn + 28), 4, 4);
            auto* bgBtn = Br(0.0f, 0.702f, 0.898f, (hover ? 0.18f : 0.06f) * g_kmBoxFade);
            if (bgBtn) { g_rT->FillRoundedRectangle(rrBtn, bgBtn); bgBtn->Release(); }
            auto* bdBtn = Br(0.0f, 0.898f, 1.0f, (hover ? 0.90f : 0.40f) * g_kmBoxFade);
            if (bdBtn) { g_rT->DrawRoundedRectangle(rrBtn, bdBtn, hover ? 1.5f : 1.0f); bdBtn->Release(); }
            DT_C(text, bxBtn, pyBtn, bxBtn + bwBtn, pyBtn + 28, 0.0f, 0.898f, 1.0f, 1.0f * g_kmBoxFade, g_mTF);
        };
        
        float btnW = (mW - 60) * 0.5f;
        float btnX1 = mX + 20;
        float btnX2 = mX + 40 + btnW;
        DrawModalButton(L"Connect", btnX1, btnW, g_kmConnR, py);
        DrawModalButton(L"Disconnect", btnX2, btnW, g_kmDiscR, py);
        py += 36;
        
        wchar_t status[128] = L"Status: Disconnected";
        if (SeraphKmbox_IsConnected()) {
            wsprintf(status, SeraphKmbox_IsReady() ? L"Status: Connected" : L"Status: Connected (HW Aim off)");
        }
        DT_C(status, mX, py, mX + mW, py + 20, 0.0f, 0.898f, 1.0f, 0.7f * g_kmBoxFade, g_sTF);
    }
}
#endif
/* ── TP Config Modal (overlay with fade, like KmBox setup) ─────────── */
if (g_showTpConfigModal || g_tpConfigFade > 0.001f) {
    float dt = 1.0f / 60.0f;
    if (g_showTpConfigModal) {
        float nextFade = g_tpConfigFade + dt * 6.0f;
        g_tpConfigFade = (nextFade > 1.0f) ? 1.0f : nextFade;
    } else {
        float nextFade = g_tpConfigFade - dt * 6.0f;
        g_tpConfigFade = (nextFade < 0.0f) ? 0.0f : nextFade;
    }
    
    float fade = g_tpConfigFade;
    
    if (g_tpConfigModalMode == 1) {
        /* ── Load config modal ───────────────────────────────────────── */
        float mW = 340.0f;
        float mH = 280.0f;
        float mX = (W - mW) * 0.5f;
        float mY = (H - mH) * 0.5f;
        g_tpModalR = { (LONG)mX, (LONG)mY, (LONG)(mX + mW), (LONG)(mY + mH) };
        
        /* Backdrop overlay */
        DR(0, 0, W, H, 0.0f, 0.0f, 0.0f, 0.6f * fade);
        
        auto rr = D2D1::RoundedRect(D2D1::RectF(mX, mY, mX + mW, mY + mH), 8, 8);
        auto* bg = Br(0.04f, 0.07f, 0.11f, 0.98f * fade);
        if (bg) { g_rT->FillRoundedRectangle(rr, bg); bg->Release(); }
        auto* border = Br(0.0f, 0.898f, 1.0f, 0.4f * fade);
        if (border) { g_rT->DrawRoundedRectangle(rr, border, 1.5f); border->Release(); }
        
        DT_C(L"Load TP Config", mX, mY + 12, mX + mW, mY + 36, 0.0f, 0.898f, 1.0f, 1.0f * fade, g_mTF);
        
        /* Close X button */
        float cx = mX + mW - 32;
        float cy = mY + 12;
        g_tpCloseR = { (LONG)cx, (LONG)cy, (LONG)(cx + 20), (LONG)(cy + 20) };
        bool hoverX = (g_mX >= g_tpCloseR.left && g_mX <= g_tpCloseR.right && g_mY >= g_tpCloseR.top && g_mY <= g_tpCloseR.bottom);
        DT_C(L"X", cx, cy, cx + 20, cy + 20, 0.0f, 0.898f, 1.0f, (hoverX ? 1.0f : 0.5f) * fade, g_mTF);
        
        /* List TP config files */
        WCHAR tpConfigs[16][64] = {};
        int tpConfigsCount = ScanTpConfigsHelper(tpConfigs, 16);
        
        float listY = mY + 50;
        float itemH = 28.0f;
        float maxVisible = 6.0f;
        float listAreaH = min((float)tpConfigsCount, maxVisible) * (itemH + 6.0f);
        
        if (tpConfigsCount == 0) {
            DT(L"No TP configurations found.", mX + 20, listY + 10, 0.6f, 0.6f, 0.6f, 1.0f * fade, g_sTF);
        } else {
            int shown = 0;
            for (int i = 0; i < tpConfigsCount; i++) {
                if (shown >= (int)maxVisible) break;
                float iy = listY + shown * (itemH + 6.0f);
                float bx = mX + 20;
                float bw = mW - 40;
                RECT cfgR = { (LONG)bx, (LONG)iy, (LONG)(bx + bw), (LONG)(iy + itemH) };
                bool hover = (g_mX >= cfgR.left && g_mX <= cfgR.right && g_mY >= cfgR.top && g_mY <= cfgR.bottom);
                auto rrC = D2D1::RoundedRect(D2D1::RectF(bx, iy, bx + bw, iy + itemH), 4, 4);
                auto* bgC = Br(0.0f, 0.702f, 0.898f, (hover ? 0.18f : 0.06f) * fade);
                if (bgC) { g_rT->FillRoundedRectangle(rrC, bgC); bgC->Release(); }
                auto* bdC = Br(0.0f, 0.898f, 1.0f, (hover ? 0.90f : 0.40f) * fade);
                if (bdC) { g_rT->DrawRoundedRectangle(rrC, bdC, hover ? 1.5f : 1.0f); bdC->Release(); }
                
                const wchar_t* cfgW = tpConfigs[i];
                DT_C(cfgW, bx, iy, bx + bw, iy + itemH, 0.0f, 0.898f, 1.0f, 1.0f * fade, g_mTF);
                shown++;
            }
        }
    } else if (g_tpConfigModalMode == 2) {
        /* ── Save config modal (small, just name input + save button) ─── */
        float mW = 320.0f;
        float mH = 150.0f;
        float mX = (W - mW) * 0.5f;
        float mY = (H - mH) * 0.5f;
        g_tpModalR = { (LONG)mX, (LONG)mY, (LONG)(mX + mW), (LONG)(mY + mH) };
        
        /* Backdrop overlay */
        DR(0, 0, W, H, 0.0f, 0.0f, 0.0f, 0.6f * fade);
        
        auto rr = D2D1::RoundedRect(D2D1::RectF(mX, mY, mX + mW, mY + mH), 8, 8);
        auto* bg = Br(0.04f, 0.07f, 0.11f, 0.98f * fade);
        if (bg) { g_rT->FillRoundedRectangle(rr, bg); bg->Release(); }
        auto* border = Br(0.0f, 0.898f, 1.0f, 0.4f * fade);
        if (border) { g_rT->DrawRoundedRectangle(rr, border, 1.5f); border->Release(); }
        
        DT_C(L"Save TP Config", mX, mY + 12, mX + mW, mY + 36, 0.0f, 0.898f, 1.0f, 1.0f * fade, g_mTF);
        
        /* Close X button */
        float cx = mX + mW - 32;
        float cy = mY + 12;
        g_tpCloseR = { (LONG)cx, (LONG)cy, (LONG)(cx + 20), (LONG)(cy + 20) };
        bool hoverX = (g_mX >= g_tpCloseR.left && g_mX <= g_tpCloseR.right && g_mY >= g_tpCloseR.top && g_mY <= g_tpCloseR.bottom);
        DT_C(L"X", cx, cy, cx + 20, cy + 20, 0.0f, 0.898f, 1.0f, (hoverX ? 1.0f : 0.5f) * fade, g_mTF);
        
        /* Config name input */
        float inpX = mX + 20;
        float inpW = mW - 40;
        float inpY = mY + 48;
        RECT inpRect = { (LONG)inpX, (LONG)inpY, (LONG)(inpX + inpW), (LONG)(inpY + 32) };
        g_tpInputR = inpRect;
        bool foc = g_tpCfgNameFocused;
        bool hoverInp = (g_mX >= inpRect.left && g_mX <= inpRect.right && g_mY >= inpRect.top && g_mY <= inpRect.bottom);
        auto rrInp = D2D1::RoundedRect(D2D1::RectF(inpX, inpY, inpX + inpW, inpY + 32), 4, 4);
        auto* bgInp = Br(0.0f, 0.702f, 0.898f, (foc ? 0.18f : (hoverInp ? 0.12f : 0.06f)) * fade);
        if (bgInp) { g_rT->FillRoundedRectangle(rrInp, bgInp); bgInp->Release(); }
        auto* bdInp = Br(0.0f, 0.898f, 1.0f, (foc ? 0.90f : 0.40f) * fade);
        if (bdInp) { g_rT->DrawRoundedRectangle(rrInp, bdInp, foc ? 1.5f : 1.0f); bdInp->Release(); }
        
        const wchar_t* dispTxt = (g_tpCfgNameBuf[0] || foc) ? g_tpCfgNameBuf : L"default";
        g_rT->PushAxisAlignedClip(D2D1::RectF(inpX + 6, inpY + 2, inpX + inpW - 4, inpY + 30), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        float clipX1 = inpX + 6;
        float clipX2 = inpX + inpW - 4;
        DTail(dispTxt, clipX1, clipX2, inpY + 6, foc ? 0.8f : 0.4f, foc ? 0.85f : 0.4f, foc ? 0.9f : 0.4f, 1.0f * fade, g_mTF);
        g_rT->PopAxisAlignedClip();
        
        /* Save button */
        float saveBtnX = mX + mW * 0.5f - 50.0f;
        float saveBtnW = 100.0f;
        float saveBtnY = inpY + 45;
        g_tpSaveR = { (LONG)saveBtnX, (LONG)saveBtnY, (LONG)(saveBtnX + saveBtnW), (LONG)(saveBtnY + 30) };
        bool hoverSave = (g_mX >= g_tpSaveR.left && g_mX <= g_tpSaveR.right && g_mY >= g_tpSaveR.top && g_mY <= g_tpSaveR.bottom);
        auto rrSave = D2D1::RoundedRect(D2D1::RectF(saveBtnX, saveBtnY, saveBtnX + saveBtnW, saveBtnY + 30), 4, 4);
        auto* bgSave = Br(0.0f, 0.702f, 0.898f, (hoverSave ? 0.18f : 0.06f) * fade);
        if (bgSave) { g_rT->FillRoundedRectangle(rrSave, bgSave); bgSave->Release(); }
        auto* bdSave = Br(0.0f, 0.898f, 1.0f, (hoverSave ? 0.90f : 0.40f) * fade);
        if (bdSave) { g_rT->DrawRoundedRectangle(rrSave, bdSave, hoverSave ? 1.5f : 1.0f); bdSave->Release(); }
        DT_C(L"Save", saveBtnX, saveBtnY, saveBtnX + saveBtnW, saveBtnY + 30, 0.0f, 0.898f, 1.0f, 1.0f * fade, g_mTF);
    }
}

// ===FOOTER===
RenderNotifications();
{
    HRESULT hrEnd = g_rT->EndDraw();
    if(FAILED(hrEnd)){
        g_rT->Release(); g_rT = NULL;
    }
}
} __except(EXCEPTION_EXECUTE_HANDLER) {
    (void)GetExceptionCode();
    /* Try to end draw to avoid D2D getting stuck */
    if(g_rT){ __try { g_rT->EndDraw(); } __except(EXCEPTION_EXECUTE_HANDLER){} }
}
}
/* DX12Overlay::RenderSystemCheck/RenderLoading/RenderLogin/Destroy/
 * UpdateMouse/SetMenuVisible/IsMenuVisible/GetActiveTab/SetActiveTab/Stop/IsRunning
 * todos em d2d_engine.cpp */
extern "C"{
void Overlay_StartFeatureInit(void){
    /* Re-enabled: scans start automatically on login, exactly like Destiny 2 */
    {HANDLE _hT=CreateThread(NULL,0,AutoAttachThread,NULL,0,NULL);if(_hT)CloseHandle(_hT);}
}
BOOL Overlay_IsFeatureInitDone(void){
    return InterlockedCompareExchange(&s_featureInitDone,0,0)?TRUE:FALSE;
}
void Overlay_FlyToggle(){
    g_flyActive=!g_flyActive;
    Fly_SetEnabled(g_flyActive?TRUE:FALSE);
    Overlay_RebuildDevTab();
}
void Overlay_FlyDirToggle(){
    g_flyDirActive=!g_flyDirActive;
    FlyDir_SetEnabled(g_flyDirActive?TRUE:FALSE);
    Overlay_RebuildDevTab();
}
/* Overlay_Create / Overlay_RenderSystemCheck / Overlay_RenderLogin / Overlay_RenderLoading /
 * Overlay_SetSystemCheckResults / Overlay_Destroy / Overlay_UpdateMouse / Overlay_Stop /
 * Overlay_IsRunning / Overlay_SetStreamProofWindow / Overlay_LoadConfigSettings /
 * Overlay_SaveConfig — todos em d2d_engine.cpp. NÃO redefina aqui. */
/* RenderMenu vive aqui — wrapper extern "C": */
void Overlay_RenderMenu(){DX12Overlay::RenderMenu();}
void Overlay_SetMenuVisible(BOOL v){DX12Overlay::SetMenuVisible(!!v);}
BOOL Overlay_IsMenuVisible(void){return DX12Overlay::IsMenuVisible()?TRUE:FALSE;}
/* Overlay_LoadConfigSettings (payload-flavor) — em d2d_engine.cpp já existe mas chama
 * apenas LoadConfig(). */
void Overlay_RebuildDevTab_Impl();
void Overlay_RebuildDevTab(){
    InterlockedExchange(&s_rebuildPending, 1);
}
void Overlay_RebuildDevTab_Impl(){
    if(!g_hW) return;
    RECT r; GetClientRect(g_hW,&r);
    int W=r.right,H=r.bottom,hH=50,sW=220,fH=0;
    int cX=sW+40,cE=W-20;
    /* preserve g_gsActive UI state across rebuilds — do NOT call GameSpeed_SetSpeed/SetSlow
     * here: those set s_dirty=TRUE which triggers BYOVD_WriteVA on the NEXT render frame,
     * which can race with BYOVD_FindProcessInfo on the background thread (same driver handle). */
    if(!g_gsActive){ g_gsSpeed=1; g_gsSlow=1; }
    g_tE[1].clear();
    g_tE[2].clear();   /* SETTING tab — rebuild with current client rect */
    g_tE[3].clear();   /* DEV tab — was leaking duplicate entries on every rebuild */
    g_tE[4].clear();
    g_tE[5].clear();
    g_tE[6].clear();
    g_tE[7].clear();   /* ESP tab */
    g_tE[8].clear();   /* AIMBOT tab */
    g_tE[9].clear();   /* TELEPORTS tab */
    /* === SETTING tab content === */
    if (g_showLoadConfigWindow) {
        int pyS = hH + 70;
        g_tE[2].push_back({UE::TabButton, {cX, pyS, cX + 100, pyS + 32}, 0, 0, 0, 0, L"<- Back"});
        pyS += 45;
        
        std::vector<std::wstring> configs = GetConfigList();
        if (configs.empty()) {
            g_tE[2].push_back({UE::Label, {cX, pyS, cE, pyS + 32}, 0, 0, 0, 0, L"No configurations found."});
        } else {
            for (const auto& cfg : configs) {
                g_tE[2].push_back({UE::TabButton, {cX, pyS, cE, pyS + 32}, 0, 0, 0, 0, cfg});
                pyS += 40;
            }
        }
    } else if (g_showSaveConfigWindow) {
        int pyS = hH + 70;
        g_tE[2].push_back({UE::TabButton, {cX, pyS, cX + 100, pyS + 32}, 0, 0, 0, 0, L"<- Back"});
        pyS += 45;
        
        g_tE[2].push_back({UE::Label, {cX, pyS, cE, pyS + 24}, 0, 0, 0, 0, L"Enter configuration name:"});
        pyS += 30;
        
        g_tE[2].push_back({UE::TextInput, {cX, pyS, cE, pyS + 32}, 0, 0, 0, 0, L""});
        pyS += 40;
        
        g_tE[2].push_back({UE::TabButton, {cX, pyS, cX + 120, pyS + 32}, 0, 0, 0, 0, L"Save Now"});
    } else {
        int pyS = hH + 70;
        g_tE[2].push_back({UE::Toggle,   {cX,pyS,cE,pyS+32},&g_streamProof,0,0,0,L"Stream Proof"}); pyS+=40;
        g_tE[2].push_back({UE::TabButton,{cX,pyS,cE,pyS+32},0,0,0,0,L"Change Key"}); pyS+=40;
#ifdef SERAPH_DMA_BUILD
        {
            SeraphKmboxSettings *km = SeraphKmbox_GetSettings();
            g_kmHwAim = km->hw_aim != 0;
            g_kmAutoConn = km->auto_connect != 0;
        }
        g_tE[2].push_back({UE::Toggle,   {cX,pyS,cE,pyS+32},&g_fuserActive,0,0,0,L"Fuser Mode"}); pyS+=40;
        if(g_waitingForFuserKey){
            g_tE[2].push_back({UE::TabButton,{cX,pyS,cE,pyS+32},0,0,0,0,L"Fuser Hotkey"});
        } else {
            g_tE[2].push_back({UE::TabButton,{cX,pyS,cE,pyS+32},0,0,0,0,L"Fuser Hotkey"});
        }
        pyS+=40;
        {
            wchar_t status[64] = L"";
            wsprintf(status, L"KmBox: %s", SeraphKmbox_IsConnected() ? L"Connected" : L"Disconnected");
            g_tE[2].push_back({UE::Label,    {cX,pyS,cE,pyS+24},0,0,0,0,status}); pyS+=30;
        }
        g_tE[2].push_back({UE::TabButton,{cX,pyS,cE,pyS+32},0,0,0,0,L"⚙ KmBox Setup"}); pyS+=40;
        g_tE[2].push_back({UE::Toggle,   {cX,pyS,cE,pyS+32},&g_kmHwAim,0,0,0,L"HW Aim (KmBox)"}); pyS+=40;
        g_tE[2].push_back({UE::Toggle,   {cX,pyS,cE,pyS+32},&g_kmAutoConn,0,0,0,L"KmBox Auto-Connect"}); pyS+=40;
#endif
        g_tE[2].push_back({UE::TabButton,{W-240,H-fH-45,W-130,H-fH-17},0,0,0,0,L"Load Config"});
        g_tE[2].push_back({UE::TabButton,{W-120,H-fH-45,W-10,H-fH-17},0,0,0,0,L"Save Config"});
    }
    /* === DEV tab content === */
    {
        int pyDev = hH + 70;
        wchar_t statusBuf[128] = L"Status: Not Attached";
        wchar_t diagBuf[128]   = L"";

        if (GetDestiny2CR3() != 0) {
            if (Overlay_IsFeatureInitDone()) {
                wsprintf(statusBuf, L"Status: Attached & Ready (Base: 0x%I64X)", GetDestiny2Base());
            } else {
                wsprintf(statusBuf, L"Status: Attaching / Scanning memory...");
            }
        } else if (!BYOVD_IsReady()) {
            wsprintf(statusBuf, L"Status: DRIVER NOT READY! (Check HVCI/Secure Boot)");
        } else if (InterlockedCompareExchange(&s_attachThreadActive, 0, 0) == 1) {
            /* Diagnostic: show cheat PID, raw CR3, resolved PID and ImageName */
            {
                char _d2t[14];
                static const char e[]={0x06,0x2A,0x39,0x2A,0x3F,0x23,0x24,0x25,0x65,0x2E,0x33,0x2E,0x00};
                for(int i=0;i<12;i++) _d2t[i]=e[i]^0x4B; _d2t[12]=0;
                UINT64 rawCR3 = BYOVD_FindProcessCR3(_d2t);
                
                DWORD resolvedPid = 0;
                char resolvedName[32] = "Unknown";
                extern BOOL BYOVD_ResolveProcessByCR3(UINT64 targetCR3, DWORD* outPid, char* outName);
                BOOL resolved = BYOVD_ResolveProcessByCR3(rawCR3, &resolvedPid, resolvedName);
                
                wsprintf(diagBuf, L"CheatPID=%u CR3=0x%I64X ResPID=%u ResName=%S", 
                         GetCurrentProcessId(), rawCR3, resolvedPid, resolvedName);
            }
            if (Destiny2ProcessFound()) {
                wsprintf(statusBuf, L"Status: Game detected, attempting kernel attach...");
            } else {
                wsprintf(statusBuf, L"Status: Waiting for game to open...");
            }
        }

        g_tE[3].push_back({UE::Label, {cX, pyDev, cE, pyDev + 24}, 0, 0, 0, 0, statusBuf});
        pyDev += 30;
        if (diagBuf[0]) {
            g_tE[3].push_back({UE::Label, {cX, pyDev, cE, pyDev + 20}, 0, 0, 0, 0, diagBuf});
            pyDev += 28;
        }
        pyDev += 12;
    }
    int pyMisc=hH+70, pyPlayer=hH+70, pyMovement=hH+70, pyWeapons=hH+70, pyEsp=hH+70, pyAimbot=hH+70, pyTeleports=hH+70;
#ifndef SERAPH_EXCLUDE_ESP
    /* === ESP tab: standalone features === */
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espMasterActive,0,0,0,L"ESP Toggle"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espActive,0,0,0,L"Boxes"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_skeletonActive,0,0,0,L"Skeleton"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espDrawHealth,0,0,0,L"Health"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espDrawShield,0,0,0,L"Shield"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espDrawDistance,0,0,0,L"Distance"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espDrawName,0,0,0,L"Name"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_espTeamCheck,0,0,0,L"Team Check"});
    pyEsp+=40;
    g_tE[7].push_back({UE::Toggle,{cX,pyEsp,cE,pyEsp+32},&g_matchmakingActive,0,0,0,L"Matchmaking List"});
    pyEsp+=40;
    /* === AIMBOT tab === */
    bool aimAny = (g_aimbotActive || g_aimbotMemoryAim);
    /* Row: Aimbot toggle + gear icon for hotkey rebind */
    if(g_waitingForAimbotKey){
        g_tE[8].push_back({UE::TabButton,{cX,pyAimbot,cE,pyAimbot+32},0,0,0,0,L"Aimbot Hotkey"});
    } else {
        g_tE[8].push_back({UE::TabButton,{cE-100,pyAimbot+8,cE-84,pyAimbot+24},0,0,0,0,L"AimbotGear"});
        g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotActive,0,0,0,L"Aimbot"});
    }
    pyAimbot+=40;
    if(aimAny){
        /* Smoothing (renders right below Aimbot when active) */
        g_tE[8].push_back({UE::Slider,{cX,pyAimbot,cE,pyAimbot+32},0,&g_aimbotSmooth,1,100,L"Smoothing"});
        pyAimbot+=40;
    }
    g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotMemoryAim,0,0,0,L"Memory Aim"});
    pyAimbot+=40;
    g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotTeamCheck,0,0,0,L"Team Check"});
    pyAimbot+=40;
#ifdef SERAPH_DMA_BUILD
    g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotVisCheck,0,0,0,L"Vis Check"});
    pyAimbot+=40;
#endif
    /* --- conditional on either aimbot mode active --- */
    if(aimAny){
        /* Target selector pill + gear icon for hotkey rebind */
        if (g_waitingForAimbotTargetHeadKey) {
            g_tE[8].push_back({UE::TabButton,{cX,pyAimbot,cE,pyAimbot+32},0,0,0,0,L"Target Head Hotkey"});
        } else {
            g_tE[8].push_back({UE::TabButton,{cE-36,pyAimbot+8,cE-20,pyAimbot+24},0,0,0,0,L"TargetHeadGear"});
            g_tE[8].push_back({UE::TabButton,{cX,pyAimbot,cE,pyAimbot+32},0,0,0,0,L"TargetSel"});
        }
        pyAimbot+=40;
        /* Switch Delay toggle */
        g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotSwitchDelayActive,0,0,0,L"Switch Delay"});
        pyAimbot+=40;
        if(g_aimbotSwitchDelayActive){
            g_tE[8].push_back({UE::Slider,{cX,pyAimbot,cE,pyAimbot+24},0,&g_aimbotSwitchDelayVal,0,10,L"Delay"});
            pyAimbot+=30;
        }
    }
    /* Show FOV toggle — always visible */
    g_tE[8].push_back({UE::Toggle,{cX,pyAimbot,cE,pyAimbot+32},&g_aimbotShowFov,0,0,0,L"Show FOV"});
    pyAimbot+=40;
    /* FOV Size — always visible, smaller row */
    g_tE[8].push_back({UE::Slider,{cX,pyAimbot,cE,pyAimbot+24},0,&g_aimbotFovSize,1,100,L"FOV Size"});
    pyAimbot+=30;
    (void)pyAimbot;
#else
    (void)pyEsp; (void)pyAimbot;
#endif
}
/* Overlay_Login* / Overlay_GetMenuHotkey — em d2d_engine.cpp */

/* Helper: convert VK code to human-readable key name */
static void VKToKeyName(int vk,wchar_t* buf,int bufLen){
    if(!buf||bufLen<1)return;
    buf[0]=0;
    switch(vk){
        case VK_INSERT:      wcsncpy(buf,L"Insert",bufLen-1);break;
        case VK_DELETE:      wcsncpy(buf,L"Delete",bufLen-1);break;
        case VK_HOME:        wcsncpy(buf,L"Home",bufLen-1);break;
        case VK_END:         wcsncpy(buf,L"End",bufLen-1);break;
        case VK_PRIOR:       wcsncpy(buf,L"Page Up",bufLen-1);break;
        case VK_NEXT:        wcsncpy(buf,L"Page Down",bufLen-1);break;
        case VK_F1:case VK_F2:case VK_F3:case VK_F4:case VK_F5:case VK_F6:
        case VK_F7:case VK_F8:case VK_F9:case VK_F10:case VK_F11:case VK_F12:
            wsprintf(buf,L"F%d",vk-VK_F1+1);break;
        case VK_NUMPAD0:case VK_NUMPAD1:case VK_NUMPAD2:case VK_NUMPAD3:
        case VK_NUMPAD4:case VK_NUMPAD5:case VK_NUMPAD6:case VK_NUMPAD7:
        case VK_NUMPAD8:case VK_NUMPAD9:
            wsprintf(buf,L"Numpad %d",vk-VK_NUMPAD0);break;
        case VK_MULTIPLY:    wcsncpy(buf,L"Numpad *",bufLen-1);break;
        case VK_ADD:         wcsncpy(buf,L"Numpad +",bufLen-1);break;
        case VK_SUBTRACT:    wcsncpy(buf,L"Numpad -",bufLen-1);break;
        case VK_DECIMAL:     wcsncpy(buf,L"Numpad .",bufLen-1);break;
        case VK_DIVIDE:      wcsncpy(buf,L"Numpad /",bufLen-1);break;
        case VK_MBUTTON:     wcsncpy(buf,L"Mouse Middle",bufLen-1);break;
        case VK_XBUTTON1:    wcsncpy(buf,L"Mouse X1",bufLen-1);break;
        case VK_XBUTTON2:    wcsncpy(buf,L"Mouse X2",bufLen-1);break;
        default:
            if(vk>=VK_PAD_L2 && vk<=VK_PAD_RIGHT){
                wcsncpy(buf,ControllerInput_GetKeyName(vk),bufLen-1);
            }
            else if(vk>='A'&&vk<='Z')wsprintf(buf,L"%c",vk);
            else if(vk>='0'&&vk<='9')wsprintf(buf,L"%c",vk);
            else wsprintf(buf,L"VK 0x%02X",vk);
    }
    buf[bufLen-1]=0;
}

void Overlay_SetMenuHotkey(int vk){
    g_menuHotkey=vk;g_waitingForKey=false;
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Menu hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Menu hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForKey(void){return g_waitingForKey?TRUE:FALSE;}
void Overlay_SetWaitingForKey(BOOL w){g_waitingForKey=!!w;}
/* Overlay_GetMatchmakingActive — used by esp_overlay.cpp */
extern "C" bool Overlay_GetMatchmakingActive(void){return g_matchmakingActive;}
/* Overlay_GetFlyHotkey — em d2d_engine.cpp */
void Overlay_SetFlyHotkey(int vk){
    g_flyHotkey=vk;g_waitingForFlyKey=false;Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Fly hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Fly hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForFlyKey(void){return g_waitingForFlyKey?TRUE:FALSE;}
/* Overlay_GetFlyDirHotkey — em d2d_engine.cpp */
void Overlay_SetFlyDirHotkey(int vk){
    g_flyDirHotkey=vk;g_waitingForFlyDirKey=false;Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"FlyDir hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"FlyDir hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForFlyDirKey(void){return g_waitingForFlyDirKey?TRUE:FALSE;}
/* Overlay_GetGsHotkey — em d2d_engine.cpp */
void Overlay_SetGsHotkey(int vk){
    g_gsHotkey=vk;g_waitingForGsKey=false;Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"GameSpeed hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"GameSpeed hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForGsKey(void){return g_waitingForGsKey?TRUE:FALSE;}
void Overlay_GameSpeedToggle(void){g_gsActive=!g_gsActive;if(!g_gsActive){GameSpeed_SetSpeed(1);GameSpeed_SetSlow(1);g_gsSpeed=1;g_gsSlow=1;}Overlay_RebuildDevTab();}
void Overlay_SetOpkHotkey(int vk){
    g_opkHotkey=vk;g_waitingForOpkKey=false;Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"OPK hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"OPK hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForOpkKey(void){return g_waitingForOpkKey?TRUE:FALSE;}
void Overlay_OpkToggle(void){g_opkActive=!g_opkActive;Overlay_RebuildDevTab();}
void Overlay_NumInputChar(wchar_t c){
    if(!g_numFocus||c<L'0'||c>L'9')return;
    if(g_numBufLen>=5)return;
    g_numBuf[g_numBufLen++]=c;
    g_numBuf[g_numBufLen]=0;
    int v=_wtoi(g_numBuf);
    for(auto&kv:g_tE){for(auto&e:kv.second){
        if(e.t==UE::NumberInput&&e.v==g_numFocus){
            if(v<e.min)v=e.min;if(v>e.max)v=e.max;
            *g_numFocus=v;return;
        }
    }}
}
void Overlay_NumInputBackspace(){
    if(!g_numFocus||g_numBufLen<=0)return;
    g_numBuf[--g_numBufLen]=0;
    if(g_numBufLen>0)*g_numFocus=_wtoi(g_numBuf);
}
BOOL Overlay_IsNumInputFocused(){return g_numFocus?TRUE:FALSE;}
void Overlay_NumInputDefocus(){g_numFocus=nullptr;g_numBufLen=0;g_numBuf[0]=0;}
BOOL Overlay_IsTextInputFocused(){
#ifdef SERAPH_DMA_BUILD
    return (g_ncNameFocused || g_cfgNameFocused || g_tpNameFocused || g_tpCfgNameFocused || g_kmFocusTag[0])?TRUE:FALSE;
#else
    return (g_ncNameFocused || g_cfgNameFocused || g_tpNameFocused || g_tpCfgNameFocused)?TRUE:FALSE;
#endif
}
void Overlay_TextInputChar(wchar_t c){
#ifdef SERAPH_DMA_BUILD
    if (g_kmFocusTag[0]) {
        wchar_t *buf = nullptr;
        int maxLen = 0, *lenPtr = nullptr;
        if (!KmBox_GetFieldBuf(g_kmFocusTag, &buf, &maxLen, &lenPtr) || !buf || !lenPtr) return;
        if (*lenPtr >= maxLen || c < 32 || c > 126) return;
        buf[(*lenPtr)++] = c;
        buf[*lenPtr] = 0;
        return;
    }
#endif
    if (g_tpNameFocused) {
        if(g_tpNameLen>=31||c<32||c>126)return;
        g_tpNameBuf[g_tpNameLen++]=(wchar_t)c;
        g_tpNameBuf[g_tpNameLen]=0;
    } else if (g_ncNameFocused) {
        if(g_ncNameLen>=31||c<32||c>126)return;
        g_ncNameBuf[g_ncNameLen++]=(wchar_t)c;
        g_ncNameBuf[g_ncNameLen]=0;
    } else if (g_cfgNameFocused) {
        if(g_cfgNameLen>=31||c<32||c>126)return;
        g_cfgNameBuf[g_cfgNameLen++]=(wchar_t)c;
        g_cfgNameBuf[g_cfgNameLen]=0;
    } else if (g_tpCfgNameFocused) {
        if(g_tpCfgNameLen>=31||c<32||c>126)return;
        g_tpCfgNameBuf[g_tpCfgNameLen++]=(wchar_t)c;
        g_tpCfgNameBuf[g_tpCfgNameLen]=0;
    }
}
void Overlay_TextInputBackspace(){
#ifdef SERAPH_DMA_BUILD
    if (g_kmFocusTag[0]) {
        wchar_t *buf = nullptr;
        int maxLen = 0, *lenPtr = nullptr;
        if (!KmBox_GetFieldBuf(g_kmFocusTag, &buf, &maxLen, &lenPtr) || !buf || !lenPtr) return;
        if (*lenPtr <= 0) return;
        buf[--(*lenPtr)] = 0;
        return;
    }
#endif
    if (g_tpNameFocused) {
        if(g_tpNameLen<=0)return;
        g_tpNameBuf[--g_tpNameLen]=0;
    } else if (g_ncNameFocused) {
        if(g_ncNameLen<=0)return;
        g_ncNameBuf[--g_ncNameLen]=0;
    } else if (g_cfgNameFocused) {
        if(g_cfgNameLen<=0)return;
        g_cfgNameBuf[--g_cfgNameLen]=0;
    } else if (g_tpCfgNameFocused) {
        if(g_tpCfgNameLen<=0)return;
        g_tpCfgNameBuf[--g_tpCfgNameLen]=0;
    }
}
void Overlay_TextInputDefocus(){
#ifdef SERAPH_DMA_BUILD
    g_kmFocusTag[0] = 0;
#endif
    if (g_tpNameFocused) {
        g_tpNameFocused = false;
    } else if (g_ncNameFocused) {
        g_ncNameFocused=false;
        char _u8[32]={};
        WideCharToMultiByte(CP_UTF8,0,g_ncNameBuf,-1,_u8,32,NULL,NULL);
        NameChanger_SetName(_u8[0]?_u8:nullptr);
        if(g_ncActive)NameChanger_SetEnabled(TRUE);
    }
    if (g_cfgNameFocused) {
        g_cfgNameFocused=false;
    }
    if (g_tpCfgNameFocused) {
        g_tpCfgNameFocused=false;
    }
}
/* Overlay_AddNotification / Overlay_AddNotificationEx — em d2d_engine.cpp */
/* Overlay_GetAimbotHotkey — em d2d_engine.cpp */
void Overlay_SetAimbotHotkey(int vk){
    g_aimbotHotkey=vk;g_waitingForAimbotKey=false;Aimbot_SetKey(vk);Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Aimbot hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Aimbot hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForAimbotKey(void){return g_waitingForAimbotKey?TRUE:FALSE;}
void Overlay_SetAimbotTargetHeadHotkey(int vk){
    g_aimbotTargetHeadHotkey=vk;g_waitingForAimbotTargetHeadKey=false;Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Target Head/Body hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Target Head/Body hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForAimbotTargetHeadKey(void){return g_waitingForAimbotTargetHeadKey?TRUE:FALSE;}
void Overlay_AimbotTargetHeadToggle(void){
    g_aimbotHeadTarget = !g_aimbotHeadTarget;
    Aimbot_SetTargetHead(g_aimbotHeadTarget ? TRUE : FALSE);
    Overlay_SaveConfig();
    Overlay_RebuildDevTab();
    Overlay_AddNotificationEx(L"Aimbot Target", g_aimbotHeadTarget ? L"Mode: Head" : L"Mode: Body", 2.0f);
}
/* Overlay_GetSuicideHotkey — em d2d_engine.cpp */
void Overlay_SetSuicideHotkey(int vk){
    g_suicideHotkey=vk;g_waitingForSuicideKey=false;Suicide_SetHotkey(vk);Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Suicide hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Suicide hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForSuicideKey(void){return g_waitingForSuicideKey?TRUE:FALSE;}
void Overlay_SetFuserHotkey(int vk){
    g_fuserHotkey=vk;g_waitingForFuserKey=false;
    if(vk>0){
        wchar_t kb[32];VKToKeyName(vk,kb,32);wchar_t msg[80];wsprintf(msg,L"Fuser hotkey set to %s",kb);
        Overlay_AddNotificationEx(L"Hotkey Set",msg,NOTIF_HOTKEY_DUR);
    } else {
        Overlay_AddNotificationEx(L"Hotkey Cleared",L"Fuser hotkey cleared",NOTIF_HOTKEY_DUR);
    }
}
BOOL Overlay_IsWaitingForFuserKey(void){return g_waitingForFuserKey?TRUE:FALSE;}
void Overlay_UpdateRightMouse(int x, int y, BOOL rightDown){DX12Overlay::UpdateRightMouse(x,y,rightDown?true:false);}
BOOL Overlay_IsWaitingForTpKey(void){return g_waitingForTpKey?TRUE:FALSE;}
int  Overlay_GetTpWaitingSlot(void){return g_tpWaitingSlot;}
void Overlay_SetTpHotkey(int vk){
    TP_SetHotkey(g_tpWaitingSlot, vk);
    g_waitingForTpKey = false;
    Overlay_RebuildDevTab();
    if(vk>0){
        wchar_t kb[32]; VKToKeyName(vk,kb,32);
        wchar_t msg[80]; wsprintf(msg,L"TP slot %d hotkey set to %s", g_tpWaitingSlot, kb);
        Overlay_AddNotificationEx(L"TP Hotkey Set", msg, NOTIF_HOTKEY_DUR);
    } else {
        wchar_t msg[80]; wsprintf(msg,L"TP slot %d hotkey cleared", g_tpWaitingSlot);
        Overlay_AddNotificationEx(L"TP Hotkey Cleared", msg, NOTIF_HOTKEY_DUR);
    }
}
}
