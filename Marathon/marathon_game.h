#pragma once
#include <windows.h>
#include <vector>
#include <string>

// Provedores matematicos simples
typedef struct {
    float x, y, z;
} MVector3;

typedef struct {
    float x, y;
} MVector2;

typedef struct {
    float m[16];
} MMatrix4x4;

typedef struct {
    UINT16    schindlerIdx;
    std::string name;
    UINT64    objectPtr;
    UINT16    listIdx;
    UINT64    entityPtr;
    UINT32    teamId;
    MVector3  basePosLow;
    MVector3  headPos;
    MVector3  basePosHigh;
    BOOL      isLocal;
    float     health;
    float     shield;
} MPlayer;

#ifdef __cplusplus
extern "C" {
#endif

// API Principal do Marathon Game
BOOL Marathon_Init(void);
extern "C" void Marathon_Tick(void);
extern "C" void Marathon_RenderESP(float screen_w, float screen_h);
BOOL Marathon_GetViewProj(MMatrix4x4* outMatrix);
BOOL Marathon_GetLocalPos(MVector3* outPos);
UINT32 Marathon_GetLocalTeam(void);
const std::vector<MPlayer>& Marathon_GetPlayers(void);

// Funcoes de utilidade
BOOL Marathon_WorldToScreen(const MVector3& worldPos, MVector2& screenPos, const MMatrix4x4& vp, float screenWidth, float screenHeight);

#ifdef __cplusplus
}
#endif
