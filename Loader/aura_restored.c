Created At: 2026-06-03T12:43:54Z
Completed At: 2026-06-03T12:43:55Z
File Path: `file:///c:/Users/leona/Downloads/Seraph%20folder/Seraph/Loader/gui_core.cpp`
Total Lines: 2343
Total Bytes: 118005
Showing lines 1 to 800
The following code has been modified to include a line number before every line, in the format: <line_number>: <original_line>. Please note that any changes targeting the original code should remove the line number, colon, and leading space.
#include <windows.h>
#include "d2d_engine.h"  /* motor D2D puro — Create/Destroy/RenderLogin/RenderSystemCheck/RenderLoading + Login* + Config */
#include "gui_core.h"
#include "gui.h"
#include "Resource.h"
#include "config_crypto.h"
#include "debug.h"
#include "attach.h"
#include "patch.h"
#include "d2_patches.h"
#include "cave_finder.h"
#include "fly.h"
/* #include "ammo.h" -- disabled: patterns outdated, pending AOB update */
#include "gamespeed.h"
#include "damage.h"
#include "aura.h"
#include "guardian.h"
#include "health_regen.h"
#include "noturnback.h"
#include "nojoinallies.h"
#include "noinactivity.h"
#include "immune_boss.h"
#include "interact_aura.h"
#include "instakill.h"
/* #include "chams.h"  // CHAMS: temporarily disabled */
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
#include "instant_abilities.h"
#include "kill_aura.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "lazyhook.h"
#include "lists.h"
#include "aob_cache.h"
#include "esp.h"
#include "esp_overlay.h"
#include "aimbot.h"
#include "suicide.h"
#ifdef SERAPH_DMA_BUILD
#include "seraph_kmbox.h"
#include "seraph_fuser.h"
#endif
#include <
<truncated 37487 bytes>
     GameSpeed_SetPreScanResult        (feAll[12].result);
        Guardian_SetPreScanResult         (feAll[13].result);
        ImmuneBoss_SetPreScanResult       (feAll[14].result);
        InteractAura_SetPreScanResult     (feAll[15].result);
        InfiniteAmmo_SetPreScanResult     (feAll[17].result);
        PlayerCloner_SetPreScanResult     (feAll[18].result);
        AmmoBrick_SetPreScanResult        (feAll[19].result);
        HSpeed_SetPreScanResult           (feAll[20].result);
        MSpeed_SetPreScanResult           (feAll[21].result);

        /* ── Informational: log which multi-scan AOBs missed.  This is just
         * for diagnostics — the actual all-OK decision happens AFTER all
         * OnAttach calls finish, using each feature's IsReady() so that a
         * fallback individual-scan success still counts as ready. */
        {
            struct { int idx; const char* name; } req[] = {
                { 0,"Damage"},      { 1,"Aura"},        { 2,"HealthRegen"},
                { 4,"Fly cam"},     { 5,"Fly pobj"},    { 6,"Havok hkp"},
                /* 7=Chams disabled; shifted: */
                { 7,"RapidFire"},   { 8,"InstAbils"},
                { 9,"NoTurnBack"},  {10,"NoJoinAllies"}, {11,"KillAura"},
                {12,"GameSpeed"},  {13,"Guardian"},      {14,"ImmuneBoss"},
                {15,"InteractAura"}, {16,"InfiniteAmmo"}, {17,"PlayerCloner"}, {18,"AmmoBrick"}, {19,"HandlingSpeed"}, {20,"MovementSpeed"},
            };
            for (int i = 0; i < (int)(sizeof(req)/sizeof(req[0])); i++) {
                if (!feAll[req[i].idx].result) {
                    char b[160];
The above content does NOT show the entire file contents. If you need to view any lines of the file which were not shown to complete your task, call this tool again to view those lines.