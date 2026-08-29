#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const UINT8 k_act_pat[];
extern const UINT8 k_act_mask[];
extern const UINT8 k_act_pat_fallback[];
extern const UINT8 k_act_mask_fallback[];
extern const UINT8 k_brick_pat[];
extern const UINT8 k_brick_mask[];
extern const UINT8 k_aura_pat[];
extern const UINT8 k_aura_mask[];
extern const UINT8 k_dmg_pat[];
extern const UINT8 k_dmg_mask[];
extern const UINT8 k_cam_pat[];
extern const UINT8 k_cam_mask[];
extern const UINT8 k_gs_pat[];
extern const UINT8 k_gs_mask[];
extern const UINT8 k_gsize_pat[];
extern const UINT8 k_gsize_mask[];
extern const UINT8 k_hs_pat[];
extern const UINT8 k_hs_mask[];
extern const UINT8 k_hrg_pat[];
extern const UINT8 k_hrg_mask[];
extern const UINT8 k_ib_pat[];
extern const UINT8 k_ib_mask[];
extern const UINT8 k_ammo_pat[];
extern const UINT8 k_ammo_mask[];
extern const UINT8 k_ik_pat[];
extern const UINT8 k_ik_mask[];
extern const UINT8 k_ia_pat[];
extern const UINT8 k_ia_mask[];
extern const UINT8 k_itar_pat[];
extern const UINT8 k_itar_mask[];
extern const UINT8 k_killaura_pat[];
extern const UINT8 k_killaura_mask[];
extern const UINT8 k_ms_pat[];
extern const UINT8 k_ms_mask[];
extern const UINT8 k_noact_pat[];
extern const UINT8 k_noact_mask[];
extern const UINT8 k_nja_pat[];
extern const UINT8 k_nja_mask[];
extern const UINT8 k_ntb_pat[];
extern const UINT8 k_ntb_mask[];
extern const UINT8 k_norecoil_pat[];
extern const UINT8 k_norecoil_mask[];
extern const UINT8 k_cloner_pat[];
extern const UINT8 k_cloner_mask[];
extern const UINT8 k_rof_pat[];
extern const UINT8 k_rof_mask[];
extern const UINT8 k_silent_pat[];
extern const UINT8 k_silent_mask[];

/* Moved from lists.h */
extern const UINT8 k_hkp_pat[];
extern const UINT8 k_hkp_mask[];
extern const UINT8 k_plarr_pat[];
extern const UINT8 k_plarr_mask[];

/* Moved from esp.h */
extern const UINT8 gp_pre_pat[];
extern const UINT8 gp_pre_mask[];
extern const UINT8 dt_pat[];
extern const UINT8 dt_mask[];

/* Moved from inventory.c */
extern const UINT8 k_inv_pat[];
extern const UINT8 k_inv_mask[];

/* Moved from ammo.c */
extern const UINT8 k_ammo_jmp_sig[];
extern const UINT8 k_ammo_jmp_mask[];
extern const UINT8 k_getkey_sig[];
extern const UINT8 k_getkey_mask[];

/* Moved from d2_patches.c */
extern const UINT8 k_istk_pat[];
extern const UINT8 k_istk_mask[];
extern const UINT8 k_spw_pat[];
extern const UINT8 k_spw_mask[];
extern const UINT8 k_stw_pat[];
extern const UINT8 k_stw_mask[];
extern const UINT8 k_itim_pat[];
extern const UINT8 k_itim_mask[];
extern const UINT8 k_gmode_pat[];
extern const UINT8 k_gmode_mask[];
extern const UINT8 k_idash_pat[];
extern const UINT8 k_idash_mask[];
extern const UINT8 k_swa_pat[];
extern const UINT8 k_swa_mask[];
extern const UINT8 k_itok_pat[];
extern const UINT8 k_itok_mask[];
extern const UINT8 k_sgs_pat[];
extern const UINT8 k_sgs_mask[];
extern const UINT8 k_ifc_pat[];
extern const UINT8 k_ifc_mask[];
extern const UINT8 k_ihr_pat[];
extern const UINT8 k_ihr_mask[];
extern const UINT8 k_pvpspw_pat[];
extern const UINT8 k_pvpspw_mask[];

/* Moved from esp.c */
extern const UINT8 k1_pat[];
extern const UINT8 k1_msk[];
extern const UINT8 k2_pat[];
extern const UINT8 k2_msk[];
extern const UINT8 k3_pat[];
extern const UINT8 k3_msk[];
extern const UINT8 k4_pat[];
extern const UINT8 k4_msk[];

/* Moved from fly.c */
extern const UINT8 k_cam_det_pat[];
extern const UINT8 k_cam_det_mask[];

/* Moved from namechanger.c */
extern const UINT8 k_pat_getter[];
extern const UINT8 k_mask_getter[];
extern const UINT8 k_pat_copy[];
extern const UINT8 k_mask_copy[];
extern const UINT8 k_pat_decode[];
extern const UINT8 k_mask_decode[];

/* Dynamic globals resolution */
extern const UINT8 k_glob_lid_pat[];
extern const UINT8 k_glob_lid_mask[];
extern const UINT8 k_glob_cmv_pat[];
extern const UINT8 k_glob_cmv_mask[];

extern const UINT8 k_thirdperson_pat[];
extern const UINT8 k_thirdperson_mask[];

extern const UINT8 k_lpmgr_pat[];
extern const UINT8 k_lpmgr_mask[];

#ifdef __cplusplus
}
#endif

