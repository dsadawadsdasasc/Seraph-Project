/*
 * dma_attach.cpp  --  DMA replacement for attach.c
 *
 * Exposes the exact same C API as attach.c (GetDestiny2CR3, GetDestiny2Base,
 * AttachToDestiny2, Attach_Invalidate, etc.) so every feature file compiles
 * unchanged.
 *
 * What is dropped vs BYOVD:
 *   - No EPROCESS walk, no CR3 extraction, no PEB+0x10 read chain.
 *   - No MZ header scan fallback loop — MemProcFS resolves the base via its
 *     own module list (far more reliable and instant).
 *   - No VM_START/VM_END Themida protection — irrelevant on the DMA machine.
 *   - No BYOVD_LOCK around the attach itself — DMA_Reattach is self-contained.
 *
 * What is kept:
 *   - All OnDetach callbacks mirror BYOVD Attach_Invalidate exactly so
 *     features clean up their state correctly on game exit.
 *   - GetDestiny2CR3() returns the MemProcFS PID cast to UINT64.  Every caller
 *     just checks != 0 to confirm attachment — semantically identical.
 */

#include "dma_attach.h"
#include "dma_mem.hpp"
#include "dma_scatter_tick.h"

#include "handling_speed.h"
#include "infinite_ammo.h"

/* ── Feature cleanup declarations ──────────────────────────────────────── */
extern "C" {
    void LazyHook_RemoveAll(UINT64 cr3);
    void Patch_Reset(void);
    void Fly_ResetSoftState(void);
    void Overlay_AddNotification(const wchar_t* header, const wchar_t* body);
    void GameSpeed_OnDetach(void);
    void Damage_OnDetach(void);
    void Guardian_OnDetach(void);
    void HealthRegen_OnDetach(void);
    void Aura_OnDetach(void);
    void ImmuneBoss_OnDetach(void);
    void InstaKill_OnDetach(void);
    void Revive_OnDetach(void);
    void InteractAura_OnDetach(void);
    void AmmoBrick_OnDetach(void);
    void MSpeed_OnDetach(void);
    void LP_OnDetach(void);
    void PlayerCloner_OnDetach(void);
    void ESP_Reset(void);          /* includes Schindler cache */
    void TigerList_Reset(void);
    void SilentAim_OnDetach(void);
    void NoRecoil_OnDetach(void);
}

#include "seraph_ptr_crypt.h"

/* ── Cached state (mirrors s_d2CR3/s_d2Base/s_d2PEB in attach.c) ─────── */
static UINT64 s_cr3_enc  = 0;   /* MemProcFS PID as UINT64 encriptado */
static UINT64 s_base_enc = 0;
static UINT64 s_peb_enc  = 0;

/* ── Public accessors ───────────────────────────────────────────────────── */
extern "C" UINT64 GetDestiny2CR3(void)  { return (UINT64)SERAPH_DEC_PTR(s_cr3_enc, &s_cr3_enc);  }
extern "C" UINT64 GetDestiny2Base(void) { return (UINT64)SERAPH_DEC_PTR(s_base_enc, &s_base_enc); }
extern "C" UINT64 GetDestiny2PEB(void)  { return (UINT64)SERAPH_DEC_PTR(s_peb_enc, &s_peb_enc);  }

/* ── Destiny2ProcessFound  ─────────────────────────────────────────────── */
extern "C" BOOL Destiny2ProcessFound(void) {
    char nm[14] = {};
    static const char e[] = { 0x2F,0x2E,0x38,0x3F,0x22,0x25,0x32,0x79, 0x65,0x2E,0x33,0x2E,0x00 };
    for (int i = 0; i < 12; i++) nm[i] = e[i] ^ 0x4B;
    nm[12] = 0;
    /* VMMDLL_PidGetFromName only — must NOT Attach (AutoAttach polls this). */
    BOOL found = DMA_ProcessExists(nm);
    return found;
}

/* ── AttachToDestiny2 ──────────────────────────────────────────────────── */
extern "C" BOOL AttachToDestiny2(void) {
    s_cr3_enc = 0; s_base_enc = 0; s_peb_enc = 0;

    BOOL ok = DMA_Reattach();

    DMA_LOCK();
    if (ok) {
        UINT64 cr3  = DMA_GetCR3();
        UINT64 base = DMA_GetBase();
        UINT64 peb  = DMA_GetPEB();
        s_cr3_enc  = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_cr3_enc);
        s_base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)base, &s_base_enc);
        s_peb_enc  = (UINT64)SERAPH_ENC_PTR((PVOID)peb, &s_peb_enc);
        g_aobLogBase = base;
    }
    DMA_UNLOCK();

    if (ok) {
        /* Start victim-PC keyboard polling (idempotent — one-shot init).
         * Called OUTSIDE DMA_LOCK: InitKeyboard runs slow VMMDLL calls
         * (registry read, module dump, sig-scan) that would stall other
         * threads if we held the lock for their duration.
         * win32kbase.sys may not be mapped yet right at attach; retry once
         * after 500ms if the first attempt fails. */
        if (!DMA_InitKeyboard()) {
            Sleep(500);
            if (!DMA_InitKeyboard()) {
                Overlay_AddNotification(L"Keyboard Error", L"DMA keyboard init failed. All keys coming from operator PC.");
            }
        }
    }

    return ok;
}

extern "C" void StartAutoAttach(void) {} /* caller manages the poll loop */

/* ── Attach_Invalidate  ─────────────────────────────────────────────────── */
extern "C" void Attach_Invalidate(void) {
    DMA_LOCK();

    /* Remove hooks and restore patches while the old CR3 is still valid */
    UINT64 cr3 = (UINT64)SERAPH_DEC_PTR(s_cr3_enc, &s_cr3_enc);
    LazyHook_RemoveAll(cr3);
    Patch_Reset();
    NoRecoil_OnDetach();
    GameSpeed_OnDetach();
    Damage_OnDetach();
    Guardian_OnDetach();
    HealthRegen_OnDetach();
    ImmuneBoss_OnDetach();
    InstaKill_OnDetach();
    InteractAura_OnDetach();
    InfiniteAmmo_OnDetach();
    AmmoBrick_OnDetach();
    HSpeed_OnDetach();
    MSpeed_OnDetach();
    PlayerCloner_OnDetach();
    SilentAim_OnDetach();

    /* Feature soft-state cleanup while old PID still valid for last reads */
    ESP_Reset();
    TigerList_Reset();

    /* Zero attach-layer state so feature Tick() calls return immediately */
    s_cr3_enc  = 0;
    s_base_enc = 0;
    s_peb_enc  = 0;

    /* Drop Teeko target PID + section cache (keeps FPGA / VMMDLL session) */
    DMA_InvalidateProcessCache();
    DMA_Tick_ClearSlots();

    Fly_ResetSoftState();
    Aura_OnDetach();
    Revive_OnDetach();
    LP_OnDetach();

    /* Allow keyboard to be re-initialized on the next attach.
     * Without this, a keyboard init failure on the first attach
     * would permanently prevent retries (s_kb_inited stays false
     * and DMA_InitKeyboard is idempotent on success only). */
    DMA_ResetKeyboard();

    DMA_UNLOCK();
}

/* ── Stub implementations for features not compiled in DMA build ──────── */
