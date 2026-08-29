#ifndef SERAPH_DMA_BUILD
#include "matchmaking.h"
#include "esp.h"
#include "byovd_lock.h"
#include "attach.h"
#include "debug.h"
#include <string.h>
#include "xor_strings.h"

extern void WriteEspLogExt(const char *msg);
#ifndef NDEBUG
#define WriteEspLog(msg) WriteEspLogExt(msg)
#else
#define WriteEspLog(msg) ((void)0)
#endif


static UINT64 s_encVA = 0;
static BOOL s_ready = FALSE;
static int s_lastActiveEntries = -1;
static UINT64 s_lastDecryptedBase = 0;

BOOL Matchmaking_Init(void)
{
    if (s_ready) return TRUE;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return FALSE;

    UINT64 d2base = GetDestiny2Base();
    if (!d2base) return FALSE;

    /* AOB: "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 15 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B D8" */
    static const UINT8 pat[] = {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 
        0xE8, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x8B, 0xD8, 
        0x48, 0x85, 0xC0, 
        0x74, 0x15, 
        0x48, 0x8B, 0xC8, 
        0xE8, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x8B, 0xC8, 
        0xE8, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x8B, 0xD8
    };
    static const UINT8 msk[] = {
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 
        0xFF, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF, 
        0xFF, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF
    };

    /* Resolve s_encVA directly using secure compile-time offset */
    s_encVA = d2base + SecureReadStatic(&OBF_OFF_MatchmakingBase);
    s_ready = TRUE;
    WriteEspLog("[Matchmaking] Init successful (Secure)");
    return TRUE;
}

UINT64 Matchmaking_GetBase(void)
{
    if (!s_ready) return 0;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return 0;

    UINT64 encBase = 0;
    if (!BYOVD_ReadVA(cr3, s_encVA, &encBase, 8) || !encBase) return 0;

    /* Destiny 2 dynamic obfuscated structure resolution:
     * decrypt 8-byte pointer by reversing shifts and XOR */
    UINT64 decBase = (encBase >> 32) ^ (encBase & 0xFFFFFFFF);
    decBase = (decBase >> 13) | (decBase << (64 - 13));
    decBase ^= 0x5A5A5A5A5A5A5A5AULL;
    return decBase;
}

static MatchmakingPlayer s_players[MATCHMAKING_MAX_PLAYERS];
static int s_playerCount = 0;

void Matchmaking_Scan(void)
{
    if (!s_ready) {
        WriteEspLog("[MM] Scan: Not ready, retrying Init");
        Matchmaking_Init();
        if (!s_ready) return;
    }

    static DWORD lastScanMs = 0;
    DWORD now = GetTickCount();
    if (now - lastScanMs < 1000) return;
    lastScanMs = now;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    UINT64 spm = ESP_DecryptPtr(cr3, s_encVA);
    s_lastDecryptedBase = spm;
    if (!spm || spm < 0x10000ULL) {
        char msg[96];
        wsprintfA(msg, "[MM] Scan: Decrypted base invalid=0x%I64X (encVA=0x%I64X)", spm, s_encVA);
        WriteEspLog(msg);
        return;
    }

    int currentCount = 0;
    int activeEntries = 0;

    for (int i = 0; i < 62; i++) {
        UINT64 entry = spm + 0x41A0 * i;
        UINT32 active = 0;
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, entry + 0x3090, &active, 4);
        BYOVD_UNLOCK();

        if (active == 0) continue;
        activeEntries++;

        char identity[128] = {0};
        BYOVD_LOCK();
        BYOVD_ReadVA(cr3, entry + 0x1D90, identity, 127);
        BYOVD_UNLOCK();

        /* Log raw identity for first 5 active entries to diagnose parsing */
        if (activeEntries <= 5) {
            char diag[256];
            wsprintfA(diag, "[MM] Scan: active idx=%d identity='%s'", i, identity);
            WriteEspLog(diag);
        }

        { static const char _bh[]={0xC7,0xD0,0xC7,0xC7,0xC9,0xC0,0xFA,0xCD,0xCA,0xD6,0xD1}; /* "bubble_host" ^0xA5 */
          char _bhd[12]; for(int _i=0;_i<11;_i++) _bhd[_i]=(char)((unsigned char)_bh[_i]^0xA5u); _bhd[11]=0;
          if (strstr(identity, _bhd)) continue; }
        { static const char _up[]={0xF0,0xEB,0xEE,0xEB,0xEA,0xF2,0xEB,0x85,0xF5,0xE0,0xE0,0xF7,0x85,0xEB,0xE4,0xE8,0xE0}; /* "UNKNOWN PEER NAME" ^0xA5 */
          char _upd[18]; for(int _i=0;_i<17;_i++) _upd[_i]=(char)((unsigned char)_up[_i]^0xA5u); _upd[17]=0;
          if (strstr(identity, _upd)) continue; }

        char* name = strchr(identity, '#');
        if (name) name++; // skip the '#'
        else name = identity; // fallback

        // Check for duplicates
        BOOL isDupe = FALSE;
        for (int j = 0; j < currentCount; j++) {
            if (strcmp(s_players[j].name, name) == 0) {
                isDupe = TRUE;
                break;
            }
        }
        if (isDupe) continue;

        /* Platform detection — strings XOR-decoded at runtime */
        char platform[16];
        { static const char _unk[] = {0xF0,0xCB,0xCE,0xCB,0xCA,0xD2,0xCB}; /* "Unknown" ^0xA5 */
          for(int _i=0;_i<7;_i++) platform[_i] = (char)((unsigned char)_unk[_i]^0xA5u); platform[7] = 0; }
        { static const char _si[]={0xD6,0xD1,0xC0,0xC4,0xC8,0xCC,0xC1,0x9F}; /* "steamid:" ^0xA5 */
          char _sid[9]; for(int _i=0;_i<8;_i++) _sid[_i]=(char)((unsigned char)_si[_i]^0xA5u); _sid[8]=0;
          static const char _sp[]={0xF6,0xD1,0xC0,0xC4,0xC8}; /* "Steam" ^0xA5 */
          char _spd[6]; for(int _i=0;_i<5;_i++) _spd[_i]=(char)((unsigned char)_sp[_i]^0xA5u); _spd[5]=0;
          static const char _xb[]={0xD6,0xD1,0xD7,0x9F,0xDD,0xC7,0xCA,0xDD}; /* "str:xbox" ^0xA5 */
          char _xbd[9]; for(int _i=0;_i<8;_i++) _xbd[_i]=(char)((unsigned char)_xb[_i]^0xA5u); _xbd[8]=0;
          static const char _xp[]={0xFD,0xC7,0xCA,0xDD}; /* "Xbox" ^0xA5 */
          char _xpd[5]; for(int _i=0;_i<4;_i++) _xpd[_i]=(char)((unsigned char)_xp[_i]^0xA5u); _xpd[4]=0;
          static const char _ps[]={0xD6,0xD1,0xD7,0x9F,0xD5,0xD6,0xCB}; /* "str:psn" ^0xA5 */
          char _psd[8]; for(int _i=0;_i<7;_i++) _psd[_i]=(char)((unsigned char)_ps[_i]^0xA5u); _psd[7]=0;
          static const char _pp[]={0xF5,0xF6,0xEB}; /* "PSN" ^0xA5 */
          char _ppd[4]; for(int _i=0;_i<3;_i++) _ppd[_i]=(char)((unsigned char)_pp[_i]^0xA5u); _ppd[3]=0;
          static const char _eg[]={0xD6,0xD1,0xD7,0x9F,0xC0,0xC2,0xD6}; /* "str:egs" ^0xA5 */
          char _egd[8]; for(int _i=0;_i<7;_i++) _egd[_i]=(char)((unsigned char)_eg[_i]^0xA5u); _egd[7]=0;
          static const char _ep[]={0xE0,0xD5,0xCC,0xC6}; /* "Epic" ^0xA5 */
          char _epd[5]; for(int _i=0;_i<4;_i++) _epd[_i]=(char)((unsigned char)_ep[_i]^0xA5u); _epd[4]=0;
          if (strstr(identity, _sid)) strcpy(platform, _spd);
          else if (strstr(identity, _xbd)) strcpy(platform, _xpd);
          else if (strstr(identity, _psd)) strcpy(platform, _ppd);
          else if (strstr(identity, _egd)) strcpy(platform, _epd); }

        /* Do not skip "Unknown" platforms, as they may be valid players from unrecognized platform prefixes. */
        // if (strcmp(platform, "Unknown") == 0) continue;
        if (!name || strlen(name) == 0 || strcmp(name, "Unknown") == 0) continue;

        if (currentCount < MATCHMAKING_MAX_PLAYERS) {
            strncpy(s_players[currentCount].name, name, sizeof(s_players[currentCount].name) - 1);
            strncpy(s_players[currentCount].platform, platform, sizeof(s_players[currentCount].platform) - 1);
            currentCount++;
        }
    }
    
    s_lastActiveEntries = activeEntries;

    if (s_playerCount != currentCount) {
        char msg[96];
        wsprintfA(msg, "[MM] Scan: Finished. Active entries=%d, players parsed=%d", activeEntries, currentCount);
        WriteEspLog(msg);
    }
    s_playerCount = currentCount;
}

int Matchmaking_GetPlayers(MatchmakingPlayer* out_players, int max_players)
{
    int count = (s_playerCount < max_players) ? s_playerCount : max_players;
    if (count > 0 && out_players) {
        memcpy(out_players, s_players, count * sizeof(MatchmakingPlayer));
    }
    return s_playerCount;
}

BOOL Matchmaking_IsReady(void)
{
    return s_ready;
}

UINT64 Matchmaking_GetLastDecryptedBase(void)
{
    return s_lastDecryptedBase;
}

int Matchmaking_GetLastActiveEntries(void)
{
    return s_lastActiveEntries;
}
#endif

