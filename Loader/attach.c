
#include "ThemidaSDK.h"
#include "attach.h"
#include "byovd.h"
#include "byovd_lock.h"
#include "patch.h"
#include "aura.h"
#include "damage.h"
#include "debug.h"
#include "gamespeed.h"
#include "guardian.h"
#include "health_regen.h"
#include "immune_boss.h"
#include "instakill.h"
#include "fly.h"
#include "havok.h"
#include "silent_aim.h"
#include "infinite_ammo.h"
#include "no_recoil.h"
#include "activity_loader.h"
#include "esp.h"
#include "weapon_stats.h"
#include "thirdperson.h"
#include "spinbot.h"
#include <windows.h>

/* XOR-decode "destiny2.exe" (key=0x4B), 12 chars */
static void _DecD2(char *out) {
    static const char e[]={0x2F,0x2E,0x38,0x3F,0x22,0x25,0x32,0x79,0x65,0x2E,0x33,0x2E,0x00};
    for(int i=0;i<12;i++) out[i]=e[i]^0x4B; out[12]=0;
}
static void _DecD2W(WCHAR *out) {
    char a[14]; _DecD2(a);
    for(int i=0;i<12;i++) out[i]=(WCHAR)a[i]; out[12]=0;
}

#include "seraph_ptr_crypt.h"

static UINT64 s_d2CR3_enc  = 0;
static UINT64 s_d2Base_enc = 0;
static UINT64 s_d2PEB_enc  = 0;

/* Plain fallback cache — updated on every successful decrypt.
 * Guards against transient SeraphPtr_Decrypt MAC failures returning NULL,
 * which would break all BYOVD VA→PA translations and pattern scans. */
static volatile UINT64 s_d2CR3_fb  = 0;
static volatile UINT64 s_d2Base_fb = 0;
static volatile UINT64 s_d2PEB_fb  = 0;

UINT64 GetDestiny2CR3(void) {
    UINT64 v = (UINT64)SERAPH_DEC_PTR(s_d2CR3_enc, &s_d2CR3_enc);
    if (v) s_d2CR3_fb = v; else v = s_d2CR3_fb;
    return v;
}
UINT64 GetDestiny2Base(void) {
    UINT64 v = (UINT64)SERAPH_DEC_PTR(s_d2Base_enc, &s_d2Base_enc);
    if (v) s_d2Base_fb = v; else v = s_d2Base_fb;
    return v;
}
UINT64 GetDestiny2PEB(void) {
    UINT64 v = (UINT64)SERAPH_DEC_PTR(s_d2PEB_enc, &s_d2PEB_enc);
    if (v) s_d2PEB_fb = v; else v = s_d2PEB_fb;
    return v;
}

BOOL Destiny2ProcessFound(void) {
    if (!BYOVD_IsReady()) return FALSE;
    char _d2[14]; _DecD2(_d2);
    UINT64 cr3 = 0, peb = 0;
    return BYOVD_FindProcessInfo(_d2, &cr3, &peb);
}

/* Real implementation — no markers, fully optimized. */
static __declspec(noinline) BOOL AttachToDestiny2_Impl(void) {
    BOOL _result = FALSE;
    s_d2CR3_enc = 0; s_d2Base_enc = 0; s_d2PEB_enc = 0;

    UINT64 cr3 = 0, pebVA = 0;
    char _d2a[14]; _DecD2(_d2a);
    BYOVD_LOCK();
    BOOL fiOk = BYOVD_FindProcessInfo(_d2a, &cr3, &pebVA);
    WLFF("attach: FindProcessInfo=%d cr3=0x%I64X peb=0x%I64X", (int)fiOk, cr3, pebVA);
    if (!fiOk) { BYOVD_UNLOCK(); goto _at_end; }
    s_d2PEB_enc = (UINT64)SERAPH_ENC_PTR((PVOID)pebVA, &s_d2PEB_enc);

    if (pebVA && pebVA > 0x10000ULL) {
        /* Método 0: Se pebVA já for a ImageBase (retornada de _EPROCESS.SectionBaseAddress com MZ validado), anexa direto! */
        WORD mz0 = 0;
        if (BYOVD_ReadVA(cr3, pebVA, &mz0, 2) && mz0 == 0x5A4D) {
            WLFF("attach: M0 direct sectionBase=0x%I64X MZ=OK", pebVA);
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)pebVA, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }

        /* Método 0.5: sectionBase veio diretamente de _EPROCESS.SectionBaseAddress
         * (processo já verificado por nome). Se VA2PA falha mas o valor está no range
         * canônico de imagebase de 64-bit (> 0x7FF000000000), confiamos sem MZ. */
        if (pebVA >= 0x7FF000000000ULL && pebVA < 0x800000000000ULL && cr3 > 0x10000ULL) {
            WLFF("attach: M0.5 trusting sectionBase=0x%I64X from EPROCESS (VA2PA unavailable)", pebVA);
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)pebVA, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }

        /* Método 1: PEB+0x10 = ImageBaseAddress */
        UINT64 base = 0;
        BYOVD_ReadVA(cr3, pebVA + 0x10, &base, 8);
        WLFF("attach: M1 peb+0x10=0x%I64X", base);
        if (base >= 0x10000ULL && base < 0x800000000000ULL) {
            WORD mz1 = 0;
            if (BYOVD_ReadVA(cr3, base, &mz1, 2) && mz1 == 0x5A4D) {
                s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
                s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)base, &s_d2Base_enc);
                BYOVD_UNLOCK(); goto attached;
            }
        }

        /* Método 2: PEB.Ldr walk */
        WCHAR _d2w[14]; _DecD2W(_d2w);
        UINT64 base2 = BYOVD_GetModuleBase(cr3, pebVA, _d2w);
        WLFF("attach: M2 ldr_base=0x%I64X", base2);
        if (base2 >= 0x10000ULL && base2 < 0x800000000000ULL) {
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)base2, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }
    }


    /* Método 3: preferred base check (0x140000000) */
    {
        UINT64 prefBase = 0x140000000ULL;
        WORD mz = 0;
        BOOL r3 = BYOVD_ReadVA(cr3, prefBase, &mz, 2);
        WLFF("attach: M3 prefBase read ok=%d mz=0x%04X", (int)r3, (UINT32)mz);
        if (r3 && mz == 0x5A4D) {
            UINT32 peOff = 0;
            if (BYOVD_ReadVA(cr3, prefBase + 0x3C, &peOff, 4) && peOff < 0x1000) {
                UINT32 peSig = 0;
                if (BYOVD_ReadVA(cr3, prefBase + peOff, &peSig, 4) && peSig == 0x00004550) {
                    UINT32 sizeOfImage = 0;
                    if (BYOVD_ReadVA(cr3, prefBase + peOff + 0x50, &sizeOfImage, 4) && sizeOfImage >= 0x3200000ULL) {
                        s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
                        s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)prefBase, &s_d2Base_enc);
                        BYOVD_UNLOCK(); goto attached;
                    }
                }
            }
        }
    }

    /* Método 4: scan MZ+PE com SizeOfImage grande.
     * Pass 0: range alto 0x7FF000000000-0x800000000000 (mais rapido, mais provavel).
     * Pass 1: range completo 0x10000-0x7FFFFFFF0000 (cobre ASLR amplo do Win11 24H2). */
    /* Método 4: scan ASLR otimizado [0x7FF600000000-0x7FFFFFFF0000] em alinhamento de 2MB */
    {
        WLFF("attach: M4 quick ASLR scan [0x7FF600000000-0x7FFFFFFF0000]");
        for (UINT64 addr = 0x7FF600000000ULL; addr < 0x7FFFFFFF0000ULL; addr += 0x200000ULL) {
            WORD mz = 0;
            if (!BYOVD_ReadVA(cr3, addr, &mz, 2) || mz != 0x5A4D) continue;
            UINT32 peOff = 0;
            if (!BYOVD_ReadVA(cr3, addr + 0x3C, &peOff, 4) || peOff >= 0x1000) continue;
            UINT32 peSig = 0;
            if (!BYOVD_ReadVA(cr3, addr + peOff, &peSig, 4) || peSig != 0x00004550) continue;
            UINT32 sizeOfImage = 0;
            if (!BYOVD_ReadVA(cr3, addr + peOff + 0x50, &sizeOfImage, 4)) continue;
            if (sizeOfImage < 0x3200000ULL) continue;
            WLFF("attach: M4 FOUND base=0x%I64X sz=0x%X", addr, sizeOfImage);
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)addr, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }
        WLFF("attach: M4 FAILED - no large image found with cr3=0x%I64X", cr3);
    }

    BYOVD_UNLOCK();
    goto _at_end;

attached:
    _result = TRUE;
_at_end:
    return _result;
}

/* Thin VM-protected wrapper with diagnostic logs around the VM region. */
#pragma optimize("", off)
BOOL AttachToDestiny2(void) {
    WLF("attach: ENTER");
    
    /* Sanity test for SeraphPtr encryption engine */
    {
        static BOOL testDone = FALSE;
        if (!testDone) {
            testDone = TRUE;
            UINT64 val = 0x123456789ABCULL;
            volatile UINT64 encTest = 0;
            encTest = (UINT64)SERAPH_ENC_PTR((PVOID)val, &encTest);
            UINT64 decTest = (UINT64)SERAPH_DEC_PTR(encTest, &encTest);
            char testBuf[128];
            wsprintfA(testBuf, "SeraphPtr Test: original=0x%I64X enc=0x%I64X dec=0x%I64X (%s)",
                      val, encTest, decTest, (decTest == val) ? "OK" : "FAILED");
            WriteLogFile(testBuf);
        }
    }

    BOOL r = FALSE;
    VM_START
    r = AttachToDestiny2_Impl();
    VM_END

    WLFF("attach: EXIT r=%d cr3=0x%I64X base=0x%I64X",
         r, (unsigned long long)GetDestiny2CR3(), (unsigned long long)GetDestiny2Base());
    return r;
}
#pragma optimize("", on)

void StartAutoAttach(void) { /* reserved */ }

void Attach_Invalidate(void) {
    /* C-5: Hold BYOVD_LOCK across the entire invalidation sequence.
     * Prevents the render thread from calling BYOVD_WriteVA between CR3 zeroing
     * and the return of each OnDetach callback.
     * Windows CRITICAL_SECTION is reentrant by the same thread, so the internal
     * BYOVD_LOCK() calls inside OnDetach functions do NOT deadlock. */
    BYOVD_LOCK();

    /* Fix-B: Restore applied patches while s_d2CR3 is still the OLD valid CR3.
     * If we zero CR3 first, Patch_Reset() finds cr3=0 and skips the restore,
     * leaving patches applied. Then FeatureInitThread would call Patch_Reset()
     * with the NEW game's CR3 and write the old-session VAs there — BSOD risk
     * if ASLR moved the game to a different base address. */
    Patch_Reset();
    /* Restore hooks that manage their own memory (need valid CR3 — must run
     * BEFORE s_d2CR3 is zeroed, same rationale as Patch_Reset above). */
    SilentAim_OnDetach();
    InfiniteAmmo_OnDetach();
    NoRecoil_OnDetach();
    GameSpeed_OnDetach();
    Damage_OnDetach();
    Guardian_OnDetach();
    HealthRegen_OnDetach();
    Aura_OnDetach();
    ImmuneBoss_OnDetach();
    InstaKill_OnDetach();
    ActivityLoader_OnDetach();
    WeaponStats_OnDetach();
    ThirdPerson_OnDetach();
    SpinBot_OnDetach();

    s_d2CR3_enc  = 0;
    s_d2Base_enc = 0;
    s_d2PEB_enc  = 0;
    s_d2CR3_fb   = 0;
    s_d2Base_fb  = 0;
    s_d2PEB_fb   = 0;

    /* Fix-A: Invalidate the FindProcessCR3 cache so Destiny2ProcessFound()
     * re-walks the EPROCESS list on the next call instead of returning the
     * dead process's stale CR3. Without this, missCount never reaches 3,
     * Attach_Invalidate is never called, and re-attach after game restart
     * never happens. */
    BYOVD_InvalidateProcessCache();

    /* Reset all features that cache a target VA — prevents stale writes after game close */
    /* NOTE: Fly_OnDetach NOT called here - it tries to remove the camera hook via
     * LazyHook_Remove which needs a valid CR3 (already zeroed above) and would
     * corrupt the hook table if the game process died mid-frame.
     * Fly_ResetSoftState() clears all ep / SObject / TL caches so stale pointers
     * don't bleed into the next game session, without touching the cam hook state. */
    Fly_ResetSoftState();
    ESP_Reset();
    Havok_Reset();
    BYOVD_UNLOCK();
}

