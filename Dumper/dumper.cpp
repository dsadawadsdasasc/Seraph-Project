#include <windows.h>
#include <stdio.h>
#include <stdint.h>

extern "C" {
#include "../Loader/byovd.h"
#include "../Loader/attach.h"
#include "../Loader/byovd_lock.h"
#include "../Loader/d2_patches.h"
}

// ---------------------------------------------------------
// FEATURE PATTERNS (Synchronized with Loader)
// ---------------------------------------------------------
static const UINT8 k_dmg_pat[] = { 0x80, 0xB9, 0x5C, 0x09, 0x00, 0x00, 0x00, 0x74, 0x09, 0xF3, 0x0F, 0x10, 0x05 };
static const UINT8 k_dmg_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_aura_pat[] = { 0x0F, 0x10, 0x02, 0x48, 0x83, 0xC1, 0x60, 0xF3, 0x41, 0x0F, 0x7F, 0x03 };
static const UINT8 k_aura_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_hrg_pat[] = { 0x0F, 0x86, 0x00, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x4E, 0x00, 0x41, 0x8B, 0xD7 };
static const UINT8 k_hrg_mask[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF };

static const UINT8 k_ik_pat[]  = { 0xF3, 0x0F, 0x11, 0x44, 0x24, 0x50, 0x33, 0xC0, 0x8B };
static const UINT8 k_ik_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_silent_pat[]  = { 0x0F, 0x10, 0x04, 0xC1, 0x48, 0x03, 0xC0, 0x0F, 0x29, 0x45, 0xF0, 0x4C, 0x8D };
static const UINT8 k_silent_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_cam_pat[]  = { 0xF3, 0x0F, 0x10, 0x47, 0x1C, 0xF3, 0x0F, 0x5F };
static const UINT8 k_cam_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_lpep_pat[] = { 0x0F, 0x28, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x10, 0xB1, 0xC0, 0x01, 0x00, 0x00, 0x0F, 0x54, 0x35, 0x00, 0x00, 0x00, 0x00 };
static const UINT8 k_lpep_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

static const UINT8 k_pobj_pat[] = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC9, 0x74, 0x00 };
static const UINT8 k_pobj_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

static const UINT8 k_hkp_pat[]  = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xE8 };
static const UINT8 k_hkp_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

static const UINT8 k_rof_pat[]  = { 0xF3, 0x0F, 0x11, 0x86, 0x2C, 0x1A, 0x00, 0x00, 0x48, 0x2B, 0xD8 };
static const UINT8 k_rof_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_ia_pat[]  = { 0xF3,0x41,0x0F,0x5C,0xC3, 0x0F,0x2F,0xC6, 0x73,0x04, 0x44 };
static const UINT8 k_ia_mask[] = { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF };

static const UINT8 k_ntb_pat[]  = { 0x40, 0xB5, 0x01, 0xF3, 0x0F, 0x58, 0x46, 0x54 };
static const UINT8 k_ntb_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_nja_pat[]  = { 0x48, 0x8B, 0x00, 0x48, 0x01, 0x47, 0x30 };
static const UINT8 k_nja_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_killaura_pat[] = { 0x33, 0xC2, 0xE9, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x41, 0x20, 0x32, 0xC0 };
static const UINT8 k_killaura_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_gs_pat[] = { 0x80, 0x00, 0x80, 0x37, 0x00, 0x5B, 0x24, 0x49 };
static const UINT8 k_gs_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_gsize_pat[]  = { 0x00,0x00,0x80,0x3F, 0x80,0xF0,0xFA,0x02 };
static const UINT8 k_gsize_mask[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF };

static const UINT8 k_ib_pat[]  = { 0xF3, 0x0F, 0x10, 0x44, 0x86, 0x48 };
static const UINT8 k_ib_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_itar_pat[]  = { 0x8B,0x54,0x01,0x6C, 0x8B,0x4F,0x24, 0x8B,0xC1, 0xC1,0xF8,0x0D };
static const UINT8 k_itar_mask[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF,0xFF };

static const UINT8 k_ammo_pat[] = { 0x41, 0x2B, 0xD5, 0x49, 0x8B, 0xCE, 0xE8, 0x00, 0x00, 0x00, 0x00 };
static const UINT8 k_ammo_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

static const UINT8 k_cloner_pat[]  = { 0x0F,0x29,0x85, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00, 0x44,0x0F,0x28,0xBD, 0x00,0x00,0x00,0x00, 0xE9, 0x00,0x00,0x00,0x00, 0x0F,0xB6,0x47 };
static const UINT8 k_cloner_mask[] = { 0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0xFF, 0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF };

static const UINT8 k_brick_pat[]  = { 0xF3, 0x44, 0x0F, 0x11, 0x86, 0xC0, 0x01, 0x00, 0x00, 0x0F, 0x28, 0x85 };
static const UINT8 k_brick_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_hs_pat[]  = { 0x48,0x2B,0xD8, 0xF3,0x0F,0x10,0x86,0x18,0x13,0x00,0x00 };
static const UINT8 k_hs_mask[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

static const UINT8 k_ms_pat[]  = { 0xF3,0x0F,0x00,0x00,0x00,0x00,0x00,0x00, 0x44,0x0F,0xB6,0xCE, 0x0F,0x28,0xF7 };
static const UINT8 k_ms_mask[] = { 0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF };

static const UINT8 k_chams_pat[]  = { 0x0F, 0x10, 0x02, 0x48, 0x83, 0xC1, 0x60 };
static const UINT8 k_chams_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_rev_pat[]  = { 0x48, 0x89, 0x86, 0x48, 0x08, 0x00, 0x00, 0x72, 0x00, 0x0F, 0x28, 0xCE };
static const UINT8 k_rev_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF };

static const UINT8 k_revw_pat[]  = { 0x49, 0x8B, 0x96, 0x48, 0x08, 0x00, 0x00, 0x48, 0x8B, 0x08, 0x48, 0x3B, 0xCA };
static const UINT8 k_revw_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_noact_pat[]  = { 0x48,0x8D,0x2D, 0x00,0x00,0x00,0x00, 0x48,0x63,0xC7 };
static const UINT8 k_noact_mask[] = { 0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF };

static const UINT8 k_namechanger_pat[]  = { 0x48, 0x3B, 0x47, 0x48, 0x0F, 0x84, 0xC5, 0x00, 0x00, 0x00 };
static const UINT8 k_namechanger_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ---------------------------------------------------------
// GLOBAL PATTERNS (globals_*)
// ---------------------------------------------------------
static const UINT8 k_glob_world_pat[] = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC1, 0xE8 };
static const UINT8 k_glob_world_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

static const UINT8 k_glob_players_pat[] = { 0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF9 };
static const UINT8 k_glob_players_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };

static const UINT8 k_glob_chan_pat[] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA };
static const UINT8 k_glob_chan_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_glob_pool_pat[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xBD };
static const UINT8 k_glob_pool_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF };

static const UINT8 k_glob_sobj_pat[] = { 0x4C, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x75 };
static const UINT8 k_glob_sobj_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF };

static const UINT8 k_glob_vp_pat[] = { 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x35 };
static const UINT8 k_glob_vp_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };

static const UINT8 k_glob_lid_pat[] = { 0x48, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00, 0x83, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84 };
static const UINT8 k_glob_lid_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

static const UINT8 k_glob_cmv_pat[] = { 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB };
static const UINT8 k_glob_cmv_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

static const UINT8 k_glob_fov_pat[] = { 0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xF1, 0xBD };
static const UINT8 k_glob_fov_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_glob_lname_pat[] = { 0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00, 0x0F, 0xB7, 0xAA };
static const UINT8 k_glob_lname_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF };

// ---------------------------------------------------------
// CORE ARRAYS AND STRUCTURES
// ---------------------------------------------------------
static const UINT8 gp_pre_pat[]  = {0x48,0x8B,0x1D, 0,0,0,0, 0x4C,0x8B,0xF9};
static const UINT8 gp_pre_mask[] = {0xFF,0xFF,0xFF, 0,0,0,0, 0xFF,0xFF,0xFF};

static const UINT8 dt_pat[]  = {0x48,0x8B,0x05, 0,0,0,0, 0xBD};
static const UINT8 dt_mask[] = {0xFF,0xFF,0xFF, 0,0,0,0, 0xFF};

static const UINT8 cambase_pat[]  = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x05 };
static const UINT8 cambase_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

// ---------------------------------------------------------
// SOBJECT POOL PATTERNS
// ---------------------------------------------------------
static const UINT8 sobj_key4_pos_pat[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x33, 0xE8, 0xE8 };
static const UINT8 sobj_key4_pos_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_key4_hp_pat[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x63, 0xD0, 0xBE };
static const UINT8 sobj_key4_hp_mask[] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_entity_loop_pat[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x81, 0xE1, 0xFF, 0x1F, 0x00, 0x00, 0x0F, 0xAF, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x10, 0x84, 0x01, 0xC0, 0x00, 0x00, 0x00 };
static const UINT8 sobj_entity_loop_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_enc_ptr_pat[] = { 0x4C, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x83, 0xFB, 0x00, 0x74, 0x00, 0x81, 0xE3 };
static const UINT8 sobj_enc_ptr_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xFF };

static const UINT8 sobj_pool_root_1_pat[] = { 0x48, 0x89, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x43, 0x20 };
static const UINT8 sobj_pool_root_1_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_pool_root_2_pat[] = { 0x48, 0x89, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x43, 0x20, 0x33, 0xD2 };
static const UINT8 sobj_pool_root_2_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_pool_array_1_pat[] = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x40, 0x18 };
static const UINT8 sobj_pool_array_1_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 sobj_pool_array_2_pat[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x00, 0x48, 0x8B, 0x40, 0x18 };
static const UINT8 sobj_pool_array_2_mask[] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

// ---------------------------------------------------------
// PATCH PATTERNS
// ---------------------------------------------------------
static const UINT8 k_istk_pat[]  = { 0x83, 0x7F, 0x2C, 0xFF, 0x89, 0x5F, 0x30 };
static const UINT8 k_istk_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_spw_pat[]  = { 0x83, 0xBE, 0x40, 0x34, 0x00, 0x00, 0x00, 0x75, 0x00 };
static const UINT8 k_spw_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

static const UINT8 k_stw_pat[]  = { 0x0F,0x11,0x02, 0x0F,0x11,0x4A,0x10, 0x44,0x0F,0x28,0x0D, 0x00,0x00,0x00,0x00, 0x44 };
static const UINT8 k_stw_mask[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00, 0xFF };

static const UINT8 k_itim_pat[]  = { 0x48,0x2B,0xC8, 0x48,0x89,0x8B,0xA0,0x00,0x00,0x00 };
static const UINT8 k_itim_mask[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

static const UINT8 k_gmode_pat[]  = { 0x33,0xDA, 0xC1,0xC3,0x10, 0xE8,0x00,0x00,0x00,0x00, 0x48 };
static const UINT8 k_gmode_mask[] = { 0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0x00,0x00,0x00,0x00, 0xFF };

static const UINT8 k_idash_pat[]  = { 0x89, 0x46, 0x34, 0x89, 0x6E, 0x3C };
static const UINT8 k_idash_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const UINT8 k_itok_pat[]  = { 0x83,0x7B,0x18,0xFF, 0x75,0x00, 0xE8,0x00,0x00,0x00,0x00, 0x89,0x43,0x18 };
static const UINT8 k_itok_mask[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0x00, 0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF };

static const UINT8 k_sgs_pat[]  = { 0x28,0xD3,0xF3,0x0F,0x58,0x49,0x00,0xF3,0x0F,0x59,0x51,0x00,0x8B,0x41 };
static const UINT8 k_sgs_mask[] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0xFF,0xFF };

static const UINT8 k_ifc_pat[]  = { 0x48,0x89,0x87,0xF8,0x01,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x48,0x83,0x7F,0x10 };
static const UINT8 k_ifc_mask[] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF };

static const UINT8 k_ihr_pat[]  = { 0xF3,0x41,0x0F,0x10,0x5C,0x24,0x00,0x4C,0x8B };
static const UINT8 k_ihr_mask[] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0xFF,0xFF };

static const UINT8 k_pvpspw_pat[]  = { 0x44,0x38,0x78,0x00,0x74,0x00,0x41,0xBF,0x04,0x00,0x00,0x00 };
static const UINT8 k_pvpspw_mask[] = { 0xFF,0xFF,0xFF,0x00,0xFF,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

extern "C" {
void Damage_OnDetach(void) {}
void Aura_OnDetach(void) {}
void Patch_Reset(void) {}
void GameSpeed_OnDetach(void) {}
void Guardian_OnDetach(void) {}
void HealthRegen_OnDetach(void) {}
void ImmuneBoss_OnDetach(void) {}
void InstaKill_OnDetach(void) {}
void Fly_ResetSoftState(void) {}
void Revive_OnDetach(void) {}
void InteractAura_OnDetach(void) {}
void InfiniteAmmo_OnDetach(void) {}
void PlayerCloner_OnDetach(void) {}
void AmmoBrick_OnDetach(void) {}
void HSpeed_OnDetach(void) {}
void MSpeed_OnDetach(void) {}
void LP_OnDetach(void) {}
void SilentAim_OnDetach(void) {}
void NoRecoil_OnDetach(void) {}
void ActivityLoader_OnDetach(void) {}
void ESP_Reset(void) {}
void Havok_Reset(void) {}
void Havok_Init(void) {}
void TigerList_Init(void) {}
void LP_ResolveGlobalsIfNeeded(UINT64 cr3, UINT64 d2Base) { (void)cr3; (void)d2Base; }
void ESP_Init(void) {}
void Keys_Init(void) {}
void WeaponStats_OnDetach(void) {}
void ThirdPerson_OnDetach(void) {}
void SpinBot_OnDetach(void) {}
size_t CaveFinder_GetReservedSize(void) { return 0; }

UINT32 g_seraphObfRoundKeys[27] = {0};
UINT32 g_seraphKeyMask = 0;
UINT64 g_seraphTweakMask = 0;
UINT64 g_seraphMacKey = 0;
volatile LONG g_seraphPtrInited = 2;
void SeraphPtr_Init(void) {}
}

// ---------------------------------------------------------
// Helper: scan a pattern across memory and return all hits
// ---------------------------------------------------------
int ScanPatternAll(UINT64 cr3, UINT64 base, UINT64 size, const UINT8* pat, const UINT8* mask, UINT8 len, UINT64 results[16]) {
    int count = 0;
    UINT64 cur = base;
    UINT64 end = base + size;
    while (cur < end && count < 16) {
        UINT64 remain = end - cur;
        BYOVD_LOCK();
        UINT64 match = BYOVD_ScanPatternRaw(cr3, cur, remain, pat, mask, len);
        BYOVD_UNLOCK();
        if (!match) break;
        results[count++] = match;
        cur = match + 1;
    }
    return count;
}

struct RipConfig {
    const char* pattern_name;
    int instr_offset;
    int disp_offset;
    int instr_len;
};

static const RipConfig k_rip_configs[] = {
    { "datum_table", 0, 3, 7 },
    { "cambase_w2s", 12, 3, 7 },
    { "sobj_enc_ptr", 0, 3, 7 },
    { "sobj_pool_root_1", 0, 3, 7 },
    { "sobj_pool_root_2", 0, 3, 7 },
    { "sobj_pool_array_1", 0, 3, 7 },
    { "sobj_pool_array_2", 0, 3, 7 },
    { "sobj_entity_loop", 0, 3, 7 },
    { "globals_tigerlist", 0, 3, 7 },
    { "globals_world_ptr", 0, 3, 7 },
    { "globals_players", 0, 3, 7 },
    { "globals_channel_manager", 0, 3, 7 },
    { "globals_handle_pool", 0, 3, 7 },
    { "globals_sobjects", 0, 3, 7 },
    { "globals_view_proj", 7, 3, 7 },
    { "globals_local_identity", 0, 3, 7 },
    { "globals_character_motion_vtable", 0, 3, 7 },
    { "globals_fov_encrypted_ptr", 0, 3, 7 },
    { "globals_local_name_ptr", 0, 3, 7 }
};

UINT64 ResolveRipOffset(UINT64 match_va, int instr_offset, int disp_offset, int instr_len, UINT64 d2Base, UINT64 cr3) {
    INT32 disp = 0;
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, match_va + instr_offset + disp_offset, &disp, 4);
    BYOVD_UNLOCK();
    if (!ok) return 0;
    UINT64 target_va = match_va + instr_offset + instr_len + (INT64)disp;
    return target_va - d2Base;
}

/* Auto-detect RIP displacement for standard x64 instructions */
BOOL AutoResolveRip(UINT64 match_va, UINT64 d2Base, UINT64 cr3, UINT64* outRVA) {
    UINT8 op[7] = {0};
    BYOVD_LOCK();
    BOOL ok = BYOVD_ReadVA_NoCache(cr3, match_va, op, 7);
    BYOVD_UNLOCK();
    if (!ok) return FALSE;

    /* MOV/LEA [RIP+disp32]: 0x48/0x4C 8B/8D ModRM where ModRM & 0xC7 == 0x05 */
    if ((op[0] == 0x48 || op[0] == 0x4C) && (op[1] == 0x8B || op[1] == 0x8D || op[1] == 0x89) && ((op[2] & 0xC7) == 0x05)) {
        INT32 disp = *(INT32*)(&op[3]);
        UINT64 target_va = match_va + 7 + (INT64)disp;
        *outRVA = target_va - d2Base;
        return TRUE;
    }
    /* MOVAPS/MOVSS [RIP+disp32]: 0x0F 0x28/0x10 ModRM where ModRM & 0xC7 == 0x05 */
    if (op[0] == 0x0F && (op[1] == 0x28 || op[1] == 0x10) && ((op[2] & 0xC7) == 0x05)) {
        INT32 disp = *(INT32*)(&op[3]);
        UINT64 target_va = match_va + 7 + (INT64)disp;
        *outRVA = target_va - d2Base;
        return TRUE;
    }
    return FALSE;
}

struct PatternConfig {
    const char* name;
    const UINT8* pat;
    const UINT8* mask;
    UINT8 len;
};

int main() {
    printf("==========================================\n");
    printf("        Seraph Live Dumper - BYOVD        \n");
    printf("==========================================\n");

    if (!BYOVD_Init()) {
        printf("[!] Failed to initialize BYOVD driver. Make sure CtiIo64.sys is loaded or run as admin.\n");
        return 1;
    }
    printf("[+] BYOVD initialized.\n");

    printf("[*] Waiting for Destiny 2 process...\n");
    while (!Destiny2ProcessFound()) {
        Sleep(1000);
    }
    
    int retries = 0;
    while (GetDestiny2CR3() == 0 && retries < 10) {
        if (AttachToDestiny2()) {
            break;
        }
        Sleep(500);
        retries++;
    }

    UINT64 cr3 = GetDestiny2CR3();
    UINT64 d2Base = GetDestiny2Base();
    if (!cr3 || !d2Base) {
        printf("[!] Failed to attach to Destiny 2.\n");
        BYOVD_Shutdown();
        return 1;
    }
    printf("[+] Attached to Destiny 2! CR3: 0x%I64X | Base: 0x%I64X\n", cr3, d2Base);

    /* Scan over full process module range up to 512 MB */
    UINT64 imgVA = d2Base;
    UINT64 imgLen = 0x20000000ULL;

    PatternConfig patterns[] = {
        // Core features
        { "damage", k_dmg_pat, k_dmg_mask, sizeof(k_dmg_pat) },
        { "aura", k_aura_pat, k_aura_mask, sizeof(k_aura_pat) },
        { "healthregen", k_hrg_pat, k_hrg_mask, sizeof(k_hrg_pat) },
        { "instakill", k_ik_pat, k_ik_mask, sizeof(k_ik_pat) },
        { "silentaim", k_silent_pat, k_silent_mask, sizeof(k_silent_pat) },
        { "fly_cam", k_cam_pat, k_cam_mask, sizeof(k_cam_pat) },
        { "fly_lpep", k_lpep_pat, k_lpep_mask, sizeof(k_lpep_pat) },
        { "fly_pobj", k_pobj_pat, k_pobj_mask, sizeof(k_pobj_pat) },
        { "havok", k_hkp_pat, k_hkp_mask, sizeof(k_hkp_pat) },
        { "rapidfire", k_rof_pat, k_rof_mask, sizeof(k_rof_pat) },
        { "instabils", k_ia_pat, k_ia_mask, sizeof(k_ia_pat) },
        { "noturnback", k_ntb_pat, k_ntb_mask, sizeof(k_ntb_pat) },
        { "nojoinallies", k_nja_pat, k_nja_mask, sizeof(k_nja_pat) },
        { "killaura", k_killaura_pat, k_killaura_mask, sizeof(k_killaura_pat) },
        { "gamespeed", k_gs_pat, k_gs_mask, sizeof(k_gs_pat) },
        { "guardian", k_gsize_pat, k_gsize_mask, sizeof(k_gsize_pat) },
        { "immunebosses", k_ib_pat, k_ib_mask, sizeof(k_ib_pat) },
        { "interactaura", k_itar_pat, k_itar_mask, sizeof(k_itar_pat) },
        { "infiniteammo", k_ammo_pat, k_ammo_mask, sizeof(k_ammo_pat) },
        { "playercloner", k_cloner_pat, k_cloner_mask, sizeof(k_cloner_pat) },
        { "ammobrick", k_brick_pat, k_brick_mask, sizeof(k_brick_pat) },
        { "handlingspeed", k_hs_pat, k_hs_mask, sizeof(k_hs_pat) },
        { "movespeed", k_ms_pat, k_ms_mask, sizeof(k_ms_pat) },
        { "chams", k_chams_pat, k_chams_mask, sizeof(k_chams_pat) },
        { "revive_write", k_rev_pat, k_rev_mask, sizeof(k_rev_pat) },
        { "revive_read", k_revw_pat, k_revw_mask, sizeof(k_revw_pat) },
        { "noinactivity", k_noact_pat, k_noact_mask, sizeof(k_noact_pat) },

        { "namechanger", k_namechanger_pat, k_namechanger_mask, sizeof(k_namechanger_pat) },

        // Globals patterns
        { "globals_world_ptr", k_glob_world_pat, k_glob_world_mask, sizeof(k_glob_world_pat) },
        { "globals_players", k_glob_players_pat, k_glob_players_mask, sizeof(k_glob_players_pat) },
        { "globals_channel_manager", k_glob_chan_pat, k_glob_chan_mask, sizeof(k_glob_chan_pat) },
        { "globals_handle_pool", k_glob_pool_pat, k_glob_pool_mask, sizeof(k_glob_pool_pat) },
        { "globals_sobjects", k_glob_sobj_pat, k_glob_sobj_mask, sizeof(k_glob_sobj_pat) },
        { "globals_view_proj", k_glob_vp_pat, k_glob_vp_mask, sizeof(k_glob_vp_pat) },
        { "globals_local_identity", k_glob_lid_pat, k_glob_lid_mask, sizeof(k_glob_lid_pat) },
        { "globals_character_motion_vtable", k_glob_cmv_pat, k_glob_cmv_mask, sizeof(k_glob_cmv_pat) },
        { "globals_fov_encrypted_ptr", k_glob_fov_pat, k_glob_fov_mask, sizeof(k_glob_fov_pat) },
        { "globals_local_name_ptr", k_glob_lname_pat, k_glob_lname_mask, sizeof(k_glob_lname_pat) },

        // Core arrays and structures
        { "globals_tigerlist", gp_pre_pat, gp_pre_mask, sizeof(gp_pre_pat) },
        { "datum_table", dt_pat, dt_mask, sizeof(dt_pat) },
        { "cambase_w2s", cambase_pat, cambase_mask, sizeof(cambase_pat) },

        // SObject pool patterns
        { "sobj_key4_pos", sobj_key4_pos_pat, sobj_key4_pos_mask, sizeof(sobj_key4_pos_pat) },
        { "sobj_key4_hp", sobj_key4_hp_pat, sobj_key4_hp_mask, sizeof(sobj_key4_hp_pat) },
        { "sobj_entity_loop", sobj_entity_loop_pat, sobj_entity_loop_mask, sizeof(sobj_entity_loop_pat) },
        { "sobj_pool_root_1", sobj_pool_root_1_pat, sobj_pool_root_1_mask, sizeof(sobj_pool_root_1_pat) },
        { "sobj_pool_root_2", sobj_pool_root_2_pat, sobj_pool_root_2_mask, sizeof(sobj_pool_root_2_pat) },
        { "sobj_pool_array_1", sobj_pool_array_1_pat, sobj_pool_array_1_mask, sizeof(sobj_pool_array_1_pat) },
        { "sobj_pool_array_2", sobj_pool_array_2_pat, sobj_pool_array_2_mask, sizeof(sobj_pool_array_2_pat) },
        { "sobj_enc_ptr", sobj_enc_ptr_pat, sobj_enc_ptr_mask, sizeof(sobj_enc_ptr_pat) },

        // Patches
        { "patch_infinitestacks", k_istk_pat, k_istk_mask, sizeof(k_istk_pat) },
        { "patch_sparrowanywhere", k_spw_pat, k_spw_mask, sizeof(k_spw_pat) },
        { "patch_shootthroughwalls", k_stw_pat, k_stw_mask, sizeof(k_stw_pat) },
        { "patch_infinitetimers", k_itim_pat, k_itim_mask, sizeof(k_itim_pat) },
        { "patch_godmode", k_gmode_pat, k_gmode_mask, sizeof(k_gmode_pat) },
        { "patch_infinitedash", k_idash_pat, k_idash_mask, sizeof(k_idash_pat) },
        { "patch_infinitetokens", k_itok_pat, k_itok_mask, sizeof(k_itok_pat) },
        { "patch_shotgunspread", k_sgs_pat, k_sgs_mask, sizeof(k_sgs_pat) },
        { "patch_instantfusion", k_ifc_pat, k_ifc_mask, sizeof(k_ifc_pat) },
        { "patch_instanthealth", k_ihr_pat, k_ihr_mask, sizeof(k_ihr_pat) },
        { "patch_pvpsparrow", k_pvpspw_pat, k_pvpspw_mask, sizeof(k_pvpspw_pat) }
    };
    const int N_PATTERNS = sizeof(patterns) / sizeof(patterns[0]);

    printf("[*] Starting memory scan for %d patterns over the whole module...\n", N_PATTERNS);

    char exeDir[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    char* lastSlash = strrchr(exeDir, '\\');
    if (lastSlash) *lastSlash = '\0';

    char offsetsPath[MAX_PATH];
    char logPath[MAX_PATH];
    snprintf(offsetsPath, sizeof(offsetsPath), "%s\\offsets.txt", exeDir[0] ? exeDir : ".");
    snprintf(logPath, sizeof(logPath), "%s\\dumper.log", exeDir[0] ? exeDir : ".");

    FILE *f1 = fopen("offsets.txt", "w");
    FILE *f2 = fopen(offsetsPath, "w");
    FILE *flog1 = fopen("dumper.log", "w");
    FILE *flog2 = fopen(logPath, "w");

    printf("[+] Writing offsets to: %s and ./offsets.txt\n", offsetsPath);
    printf("[+] Writing log to:     %s and ./dumper.log\n", logPath);

    if (flog1) { fprintf(flog1, "CR3: 0x%I64X | Base: 0x%I64X\n\n", cr3, d2Base); fflush(flog1); }
    if (flog2 && flog2 != flog1) { fprintf(flog2, "CR3: 0x%I64X | Base: 0x%I64X\n\n", cr3, d2Base); fflush(flog2); }

    int foundCount = 0;
    int missCount = 0;

    for (int i = 0; i < N_PATTERNS; i++) {
        UINT64 results[16] = {0};
        int hits = ScanPatternAll(cr3, imgVA, imgLen, patterns[i].pat, patterns[i].mask, patterns[i].len, results);

        if (hits == 0) {
            printf("[!] %-32s NOT FOUND\n", patterns[i].name);
            if (f1) fprintf(f1, "%s = 0\n", patterns[i].name);
            if (f2 && f2 != f1) fprintf(f2, "%s = 0\n", patterns[i].name);
            if (flog1) fprintf(flog1, "[!] %-32s NOT FOUND\n", patterns[i].name);
            if (flog2 && flog2 != flog1) fprintf(flog2, "[!] %-32s NOT FOUND\n", patterns[i].name);
            missCount++;
        }
        else if (hits == 1) {
            UINT64 offset = 0;
            BOOL resolved = FALSE;

            /* Check explicit RipConfig first */
            for (int r = 0; r < sizeof(k_rip_configs) / sizeof(k_rip_configs[0]); r++) {
                if (strcmp(patterns[i].name, k_rip_configs[r].pattern_name) == 0) {
                    offset = ResolveRipOffset(results[0], k_rip_configs[r].instr_offset, k_rip_configs[r].disp_offset, k_rip_configs[r].instr_len, d2Base, cr3);
                    resolved = TRUE;
                    break;
                }
            }

            /* Auto-detect RIP instruction if not explicitly configured */
            if (!resolved) {
                if (AutoResolveRip(results[0], d2Base, cr3, &offset)) {
                    resolved = TRUE;
                } else {
                    /* Fallback: instruction RVA */
                    offset = results[0] - d2Base;
                }
            }

            printf("[+] %-32s 0x%I64X\n", patterns[i].name, offset);
            if (f1) fprintf(f1, "%s = 0x%I64X\n", patterns[i].name, offset);
            if (f2 && f2 != f1) fprintf(f2, "%s = 0x%I64X\n", patterns[i].name, offset);
            if (flog1) fprintf(flog1, "[+] %-32s 0x%I64X\n", patterns[i].name, offset);
            if (flog2 && flog2 != flog1) fprintf(flog2, "[+] %-32s 0x%I64X\n", patterns[i].name, offset);
            foundCount++;
        }
        else {
            printf("[?] %-32s MULTIPLE (%d):", patterns[i].name, hits);
            if (flog1) fprintf(flog1, "[?] %-32s MULTIPLE (%d):", patterns[i].name, hits);
            if (flog2 && flog2 != flog1) fprintf(flog2, "[?] %-32s MULTIPLE (%d):", patterns[i].name, hits);
            for (int h = 0; h < hits; h++) {
                UINT64 h_offset = 0;
                BOOL h_resolved = FALSE;
                for (int r = 0; r < sizeof(k_rip_configs) / sizeof(k_rip_configs[0]); r++) {
                    if (strcmp(patterns[i].name, k_rip_configs[r].pattern_name) == 0) {
                        h_offset = ResolveRipOffset(results[h], k_rip_configs[r].instr_offset, k_rip_configs[r].disp_offset, k_rip_configs[r].instr_len, d2Base, cr3);
                        h_resolved = TRUE;
                        break;
                    }
                }
                if (!h_resolved) {
                    if (!AutoResolveRip(results[h], d2Base, cr3, &h_offset)) {
                        h_offset = results[h] - d2Base;
                    }
                }
                printf(" 0x%I64X%s", h_offset, (h == hits - 1) ? "" : ",");
                if (flog1) fprintf(flog1, " 0x%I64X%s", h_offset, (h == hits - 1) ? "" : ",");
                if (flog2 && flog2 != flog1) fprintf(flog2, " 0x%I64X%s", h_offset, (h == hits - 1) ? "" : ",");
            }
            printf("\n");
            if (flog1) fprintf(flog1, "\n");
            if (flog2 && flog2 != flog1) fprintf(flog2, "\n");

            UINT64 first_offset = 0;
            BOOL first_resolved = FALSE;
            for (int r = 0; r < sizeof(k_rip_configs) / sizeof(k_rip_configs[0]); r++) {
                if (strcmp(patterns[i].name, k_rip_configs[r].pattern_name) == 0) {
                    first_offset = ResolveRipOffset(results[0], k_rip_configs[r].instr_offset, k_rip_configs[r].disp_offset, k_rip_configs[r].instr_len, d2Base, cr3);
                    first_resolved = TRUE;
                    break;
                }
            }
            if (!first_resolved) {
                if (!AutoResolveRip(results[0], d2Base, cr3, &first_offset)) {
                    first_offset = results[0] - d2Base;
                }
            }
            if (f1) fprintf(f1, "%s = 0x%I64X // WARNING: MULTIPLE MATCHES (%d hits found)\n", patterns[i].name, first_offset, hits);
            if (f2 && f2 != f1) fprintf(f2, "%s = 0x%I64X // WARNING: MULTIPLE MATCHES (%d hits found)\n", patterns[i].name, first_offset, hits);
            foundCount++;
        }

        if (f1) fflush(f1);
        if (f2) fflush(f2);
        if (flog1) fflush(flog1);
        if (flog2) fflush(flog2);
    }

    if (f1) fclose(f1);
    if (f2 && f2 != f1) fclose(f2);
    if (flog1) fclose(flog1);
    if (flog2 && flog2 != flog1) fclose(flog2);

    printf("\n==========================================\n");
    printf("  Scan complete: %d found, %d missed (total %d)\n", foundCount, missCount, N_PATTERNS);
    printf("==========================================\n");

    BYOVD_Shutdown();
    return 0;
}
