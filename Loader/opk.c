#ifndef SERAPH_EXCLUDE_OPK
#include "opk.h"
#include "havok.h"
#include "fly.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"
#include <math.h>

static BOOL s_opkEnabled = FALSE;
static int  s_opkDistance = 3;

void OPK_SetEnabled(BOOL state) {
    s_opkEnabled = state;
}

BOOL OPK_IsEnabled(void) {
    return s_opkEnabled;
}

void OPK_SetDistance(int value) {
    if (value < 1) value = 1;
    if (value > 5) value = 5;
    s_opkDistance = value;
}

int OPK_GetDistance(void) {
    return s_opkDistance;
}

void OPK_Tick(void) {
    if (!s_opkEnabled) return;

    UINT64 cr3 = GetDestiny2CR3();
    if (!cr3) return;

    if (!g_HavokState.hkp_world_va) {
        Havok_Init();
    }
    if (!g_HavokState.hkp_world_va) return;

    /* --- Pegar entidades Havok ---
     * Havok_GetEntities ja filtra: sem hitbox, coords zero/NaN, sem hkpWorld.
     * O filtro correto e: qualquer entidade valida EXCETO o jogador local.
     * Chamamos isso no comeco para obter e atualizar a posicao do local player via lists.h */
    static HavokEntity entities[HAVOK_MAX_RESULTS];
    int count = Havok_GetEntities(entities, HAVOK_MAX_RESULTS);
    if (count <= 0) return;

    /* --- Posicao da camera/jogador local ---
     * Prioridade: g_camWorldPos (atualizado pelo fly tick) > local_pos do Havok.
     * Nao depende do fly estar ativo — g_camWorldPosValid e setado sempre que
     * o fly resolve a posicao, mesmo com fly desativado (loop de cam). */
    float cam_x, cam_y, cam_z;
    if (g_camWorldPosValid) {
        cam_x = g_camWorldPos.x;
        cam_y = g_camWorldPos.y;
        cam_z = g_camWorldPos.z;
    } else if (g_HavokState.local_pos.x != 0.0f ||
               g_HavokState.local_pos.y != 0.0f ||
               g_HavokState.local_pos.z != 0.0f) {
        /* Fallback: ultima posicao conhecida do jogador local via Havok */
        cam_x = g_HavokState.local_pos.x;
        cam_y = g_HavokState.local_pos.y;
        cam_z = g_HavokState.local_pos.z;
    } else {
        /* Sem referencia de posicao valida */
        return;
    }

    /* --- Angulos de camera ---
     * Usar trig cache do fly (s_cosY/sinY/cosP/sinP) via Fly_GetCamTrig.
     * Se o cache nao estiver pronto (fly nunca rodou), tentar Fly_ReadCam. */
    float cosY, sinY, cosP, sinP;
    Fly_GetCamTrig(&cosY, &sinY, &cosP, &sinP);

    /* Detectar cache invalido (valores default = cosY=1,sinY=0,cosP=1,sinP=0).
     * Nesse caso tentar leitura direta. Se falhar, usar frente (yaw=0). */
    if (cosY == 1.0f && sinY == 0.0f) {
        float yaw = 0.0f, pitch = 0.0f;
        if (Fly_ReadCam(&yaw, &pitch, NULL)) {
            cosY = cosf(yaw);  sinY = sinf(yaw);
            cosP = cosf(pitch); sinP = sinf(pitch);
        }
        /* else: usar direcao padrao (frente), ainda util para engajar */
    }

    /* --- Ponto alvo: dist unidades na direcao da camera --- */
    float dist = (float)s_opkDistance;
    float target[3];
    target[0] = cam_x + cosY * cosP * dist;  /* East  */
    target[1] = cam_y + sinY * cosP * dist;  /* North */
    target[2] = cam_z - sinP * dist;         /* Height */

    UINT64 localPlayerEp = g_HavokState.local_entity_ptr;

    for (int i = 0; i < count; i++) {
        UINT64 ep = entities[i].entity_ptr;
        if (!ep) continue;

        /* Pular o jogador local */
        if (ep == localPlayerEp) continue;

        /* Pular entidades com vtable identico ao local player (outros dados
         * que o Havok identifica como hkpCharacterMotion — nao sao alvos). */
        if (g_HavokState.hkp_motion_vtable &&
            entities[i].motion_vtable == g_HavokState.hkp_motion_vtable) continue;

        BYOVD_LOCK();
        /* Teleportar coordenadas para o ponto alvo (RB_OFF_COORDS = 0x1C0) */
        BYOVD_WriteVA(cr3, ep + RB_OFF_COORDS, target, sizeof(target));
        BYOVD_UNLOCK();
    }
}
#endif
