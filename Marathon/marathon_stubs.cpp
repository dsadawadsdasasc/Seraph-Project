#include <windows.h>

typedef struct {
    UINT64  datum_table_va;
    UINT32  key1;
    UINT32  key2;
    UINT32  key3;
    UINT32  key4;
    BOOL    keys_valid;
    BOOL    datum_valid;
    UINT64  view_mat_va;
    UINT64  proj_mat_va;
    BOOL    matrices_valid;
    UINT64  g_players_va;
    BOOL    tl_valid;
} EspState_t;

extern "C" EspState_t g_EspState = {0};

// Structs dummies para compilar
struct TPSlot {
    bool valid;
    wchar_t name[32];
    float x, y, z;
};

// Patches & Patterns (C Linkage matching Seraph headers)
extern "C" const unsigned char k_cam_mask[1] = {0};
extern "C" const unsigned char k_cam_pat[1] = {0};
extern "C" const unsigned char k_dmg_mask[1] = {0};
extern "C" const unsigned char k_dmg_pat[1] = {0};
extern "C" const unsigned char k_gs_mask[1] = {0};
extern "C" const unsigned char k_gs_pat[1] = {0};
extern "C" const unsigned char k_gsize_mask[1] = {0};
extern "C" const unsigned char k_gsize_pat[1] = {0};
extern "C" const unsigned char k_hrg_mask[1] = {0};
extern "C" const unsigned char k_hrg_pat[1] = {0}; // changed to C linkage
extern "C" const unsigned char k_ib_mask[1] = {0};
extern "C" const unsigned char k_ib_pat[1] = {0};
extern "C" const unsigned char k_itar_mask[1] = {0};
extern "C" const unsigned char k_itar_pat[1] = {0};
extern "C" const unsigned char k_nja_mask[1] = {0};
extern "C" const unsigned char k_nja_pat[1] = {0};
extern "C" const unsigned char k_ntb_mask[1] = {0};
extern "C" const unsigned char k_ntb_pat[1] = {0};
extern "C" const unsigned char k_ik_pat[1] = {0};
extern "C" const unsigned char k_ik_mask[1] = {0};
extern "C" const unsigned char k_rof_pat[1] = {0};
extern "C" const unsigned char k_rof_mask[1] = {0};
extern "C" const unsigned char k_ammo_pat[1] = {0};
extern "C" const unsigned char k_ammo_mask[1] = {0};
extern "C" const unsigned char k_brick_pat[1] = {0};
extern "C" const unsigned char k_brick_mask[1] = {0};
extern "C" const unsigned char k_hs_pat[1] = {0};
extern "C" const unsigned char k_hs_mask[1] = {0};
extern "C" const unsigned char k_ms_pat[1] = {0};
extern "C" const unsigned char k_ms_mask[1] = {0};
extern "C" const unsigned char k_cloner_pat[1] = {0};
extern "C" const unsigned char k_cloner_mask[1] = {0};
extern "C" const unsigned char k_ia_pat[1] = {0};
extern "C" const unsigned char k_ia_mask[1] = {0};
extern "C" const unsigned char k_killaura_pat[1] = {0};
extern "C" const unsigned char k_killaura_mask[1] = {0};
extern "C" const unsigned char k_hkp_pat[1] = {0};
extern "C" const unsigned char k_hkp_mask[1] = {0};
extern "C" const unsigned char k_silent_pat[1] = {0};
extern "C" const unsigned char k_silent_mask[1] = {0};
extern "C" const unsigned char k_norecoil_pat[1] = {0};
extern "C" const unsigned char k_norecoil_mask[1] = {0};

extern "C" {

    int Patch_Count() { return 0; }
    const char* Patch_GetName(int) { return nullptr; }
    bool Patch_IsApplied(int) { return false; }
    void Patch_Reset() {}
    void Patch_SetBytes(int, const unsigned char*, size_t) {}
    void Patch_Toggle(int, bool) {}

    // Aimbot D2
    float Aimbot_GetFovPx() { return 0.0f; }
    bool Aimbot_GetShowFov() { return false; }
    void Aimbot_SetEnabled(BOOL) {}
    void Aimbot_SetFovSize(int) {}
    void Aimbot_SetKey(int) {}
    void Aimbot_SetMemoryAim(BOOL) {}
    void Aimbot_SetShowFov(BOOL) {}
    void Aimbot_SetSmooth(int) {}
    void Aimbot_SetSwitchDelay(float) {}
    void Aimbot_SetTargetHead(BOOL) {}
    void Aimbot_SetTeamCheck(BOOL) {}
    void Aimbot_Tick(void*, int, float, float, void*, int) {}

    // Teleports D2
    void TP_Delete(int) {}
    int TP_GetHotkey(int) { return 0; }
    void TP_LoadConfig() {}
    void TP_SaveConfig() {}
    void TP_SaveCurrent(const wchar_t*) {}
    void TP_SetHotkey(int, int) {}
    void TP_TeleportNext() {}
    void TP_TeleportPrev() {}
    void TP_TeleportTo(int) {}
    int TP_GetCount() { return 0; }
    const TPSlot* TP_GetSlot(int) { return nullptr; }

    // Activity Loader
    void ActivityLoader_OnAttach() {}
    void ActivityLoader_OnDetach() {}
    void ActivityLoader_SetActivityId(int) {}

    // Ammo Brick
    void AmmoBrick_OnAttach() {}
    void AmmoBrick_SetEnabled(BOOL) {}
    void AmmoBrick_SetPreScanResult(void*) {}

    // Aura & Immune Aura
    void Aura_OnAttach() {}
    void Aura_SetEnabled(BOOL) {}
    void Aura_SetMultiplier(float) {}
    void Aura_Tick() {}

    // Locks

    // Bunny Hop
    void BunnyHop_SetEnabled(BOOL) {}
    void BunnyHop_SetSpeed(int) {}
    void BunnyHop_SetVertical(int) {}
    void BunnyHop_Tick() {}

    // Cave Finder
    void CaveFinder_ClearReservations() {}
    size_t CaveFinder_GetReservedSize(void) { return 0; }

    // Patches config
    int D2Patches_GetFailCount() { return 0; }
    int D2Patches_GetMutexGroup() { return 0; }
    void D2Patches_Register() {}
    int D2Patches_GetTabForId(int) { return 0; }

    // Damage Increase
    BOOL Damage_IsReady() { return FALSE; }
    void Damage_OnAttach() {}
    void Damage_SetEnabled(BOOL) {}
    void Damage_SetMultiplier(int) {}
    void Damage_SetPreScanResult(void*) {}
    void Damage_Tick() {}

    // ESP D2 stubs
    void ESP_AcquireUpdateThread() {}
    void ESP_Init() {}
    void ESP_ReleaseUpdateThread() {}
    BOOL ESP_WorldToScreen(float*, float*, float*, float*) { return FALSE; }

    // Fly Directional & Fly WASD
    void FlyDir_SetEnabled(BOOL) {}
    void Fly_OnAttach() {}
    void Fly_SetCamPreScanResult(void*) {}
    void Fly_SetEnabled(BOOL) {}
    void Fly_Tick() {}
    void Fly_ResetSoftState() {}

    // Game Speed
    BOOL GameSpeed_IsReady() { return FALSE; }
    void GameSpeed_OnAttach() {}
    void GameSpeed_OnDetach() {}
    void GameSpeed_SetPreScanResult(void*) {}
    void GameSpeed_SetSlow(int) {}
    void GameSpeed_SetSpeed(int) {}
    void GameSpeed_Tick() {}

    // Guardian Size
    int Guardian_GetValue() { return 0; }
    BOOL Guardian_IsReady() { return FALSE; }
    void Guardian_OnAttach() {}
    void Guardian_Reset() {}
    void Guardian_SetEnabled(BOOL) {}
    void Guardian_SetPreScanResult(void*) {}
    void Guardian_SetValue(int) {}
    void Guardian_Tick() {}
    void Guardian_OnDetach() {}

    // HSpeed / Fly Speed
    void HSpeed_OnAttach() {}
    void HSpeed_SetEnabled(BOOL) {}
    void HSpeed_SetMultiplier(float) {}
    void HSpeed_SetPreScanResult(void*) {}

    // Havok
    void Havok_SetHkpPreScanResult(void*) {}

    // Health Regen
    void HealthRegen_OnAttach() {}
    void HealthRegen_SetPreScanResult(void*) {}
    void HealthRegen_OnDetach() {}

    // Immune Bosses
    BOOL ImmuneBoss_IsReady() { return FALSE; }
    void ImmuneBoss_OnAttach() {}
    void ImmuneBoss_SetEnabled(BOOL) {}
    void ImmuneBoss_SetPreScanResult(void*) {}
    void ImmuneBoss_Tick() {}
    void ImmuneBoss_OnDetach() {}

    // Infinite Ammo
    void InfiniteAmmo_OnAttach() {}
    void InfiniteAmmo_SetEnabled(BOOL) {}
    void InfiniteAmmo_SetPreScanResult(void*) {}
    void InfiniteAmmo_OnDetach() {}

    // Insta Kill
    void InstaKill_OnAttach() {}
    void InstaKill_SetEnabled(BOOL) {}
    void InstaKill_SetPreScanResult(void*) {}
    void InstaKill_OnDetach() {}

    // Instant Abilities
    void InstantAbilities_OnAttach() {}
    void InstantAbilities_SetPreScanResult(void*) {}

    // Interact Aura
    void InteractAura_OnAttach() {}
    void InteractAura_SetEnabled(BOOL) {}
    void InteractAura_SetPreScanResult(void*) {}
    void InteractAura_Tick() {}

    // Keys Init
    void Keys_Init() {}

    // Kill Aura
    void KillAura_OnAttach() {}
    void KillAura_SetEnabled(BOOL) {}
    void KillAura_SetMultiplier(int) {}
    void KillAura_SetPreScanResult(void*) {}

    // Movement Speed
    void MSpeed_OnAttach() {}
    void MSpeed_SetEnabled(BOOL) {}
    void MSpeed_SetPreScanResult(void*) {}
    void MSpeed_SetValue(int) {}

    // Matchmaking
    void* Matchmaking_GetLastActiveEntries() { return nullptr; }
    UINT64 Matchmaking_GetLastDecryptedBase() { return 0; }
    void* Matchmaking_GetPlayers() { return nullptr; }
    void Matchmaking_Init() {}
    BOOL Matchmaking_IsReady() { return FALSE; }

    // Name Changer
    void NameChanger_OnAttach() {}
    void NameChanger_SetEnabled(BOOL) {}
    void NameChanger_SetName(const wchar_t*) {}
    void NameChanger_Tick() {}

    // No Inactivity
    void NoInactivity_OnAttach() {}

    // No Join Allies
    int NoJoinAllies_GetPatchId() { return 0; }
    void NoJoinAllies_OnAttach() {}
    void NoJoinAllies_SetPreScanResult(void*) {}
    void NoJoinAllies_TriggerOneShotZero() {}

    // No Recoil
    void NoRecoil_OnAttach() {}
    void NoRecoil_SetEnabled(BOOL) {}
    void NoRecoil_SetPreScanResult(void*) {}
    void NoRecoil_OnDetach() {}

    // No Turn Back
    int NoTurnBack_GetPatchId() { return 0; }
    void NoTurnBack_OnAttach() {}
    void NoTurnBack_SetPreScanResult(void*) {}
    void NoTurnBack_TriggerOneShotZero() {}

    // OPK (One Position Kill)
    void OPK_SetDistance(int) {}
    void OPK_SetEnabled(BOOL) {}
    void OPK_Tick() {}

    // Player Cloner
    void PlayerCloner_OnAttach() {}
    void PlayerCloner_SetEnabled(BOOL) {}
    void PlayerCloner_SetPreScanResult(void*) {}

    // Rapid Fire
    BOOL RapidFire_IsReady() { return FALSE; }
    void RapidFire_OnAttach() {}
    void RapidFire_SetEnabled(BOOL) {}
    void RapidFire_SetMultiplier(int) {}
    void RapidFire_SetPreScanResult(void*) {}

    // Revive
    void Revive_OnAttach() {}
    void Revive_SetEnabled(BOOL) {}
    void Revive_Tick() {}

    // Silent Aim
    void SilentAim_OnAttach() {}
    void SilentAim_SetEnabled(BOOL) {}
    void SilentAim_SetMagnetism(int) {}
    void SilentAim_SetPreScanResult(void*) {}
    void SilentAim_OnDetach() {}

    // Suicide
    void Suicide_SetHotkey(int) {}
    void Suicide_Trigger() {}

    // D2 Features stubs required by skeleton/local_player
    BOOL Fly_IsEnabled() { return FALSE; }
    BOOL FlyDir_IsEnabled() { return FALSE; }
    BOOL ESP_ReadMatrices(UINT64, float*, float*) { return FALSE; }
    void* ESP_GetEntityBoxes() { return nullptr; }
    UINT64 ESP_GetSLListBase() { return 0; }
    void* ESP_GetCachedMatrices() { return nullptr; }

    // local_player.c stubs — Loader\local_player.c is NOT compiled in Marathon
    // (it pulls fly.h which has memory writes and tigerlist.c D2 version)
    UINT64 g_local_identity_rva = 0;
    UINT64 g_character_motion_vtable_rva = 0;
    void   LP_OnAttach(void) {}
    void   LP_OnDetach(void) {}
    void   LP_Tick(void) {}
    int    LP_GetLocalPlayerIndex(void) { return -1; }
    void   LP_ResolveGlobalsIfNeeded(UINT64, UINT64) {}
    void   LP_ResetSoftState(void) {}
    UINT64 LP_GetEntityVA(void) { return 0; }

    // sobject_list.c stubs — Loader\sobject_list.c is NOT compiled in Marathon
    // (it has no guards for SERAPH_MARATHON and pulls D2-specific code)
    void SObjectList_OnAttach(void) {}
    void SObjectList_OnDetach(void) {}
    void SObjectList_Tick(void) {}


    // Locks reais para Marathon
    CRITICAL_SECTION g_byovdLock = {0};
    void BYOVD_LockInit(void) {
        InitializeCriticalSectionAndSpinCount(&g_byovdLock, 2000);
    }
    void BYOVD_LockDestroy(void) {
        DeleteCriticalSection(&g_byovdLock);
    }

}
