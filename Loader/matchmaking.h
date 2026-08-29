#pragma once
#include <windows.h>
#include "byovd.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SERAPH_DMA_BUILD
/* Initialize the matchmaking scanner. Call once after attach. */
BOOL Matchmaking_Init(void);

/* Scan the matchmaking list and update internal state. */
void Matchmaking_Scan(void);

/* Get the current state of matchmaking list (optional). */
UINT64 Matchmaking_GetBase(void);

#define MATCHMAKING_MAX_PLAYERS 64

typedef struct {
    char name[128];
    char platform[16];
} MatchmakingPlayer;

/* Get the scanned players. Returns the count. */
int Matchmaking_GetPlayers(MatchmakingPlayer* out_players, int max_players);

/* Diagnostic query functions */
BOOL Matchmaking_IsReady(void);
UINT64 Matchmaking_GetLastDecryptedBase(void);
int Matchmaking_GetLastActiveEntries(void);
#else
#define MATCHMAKING_MAX_PLAYERS 64

typedef struct {
    char name[128];
    char platform[16];
} MatchmakingPlayer;

static inline BOOL Matchmaking_Init(void) { return FALSE; }
static inline void Matchmaking_Scan(void) {}
static inline UINT64 Matchmaking_GetBase(void) { return 0; }
static inline int Matchmaking_GetPlayers(MatchmakingPlayer* out_players, int max_players) { (void)out_players; (void)max_players; return 0; }
static inline BOOL Matchmaking_IsReady(void) { return FALSE; }
static inline UINT64 Matchmaking_GetLastDecryptedBase(void) { return 0; }
static inline int Matchmaking_GetLastActiveEntries(void) { return 0; }
#endif

#ifdef __cplusplus
}
#endif

