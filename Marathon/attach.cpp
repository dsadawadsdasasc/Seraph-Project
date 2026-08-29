
#define SERAPH_MARATHON
#include "ThemidaSDK.h"
#include "attach.h"
#include "byovd.h"
extern "C" {
#include "byovd_lock.h"
}
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
#include "silent_aim.h"
#include "infinite_ammo.h"
#include "no_recoil.h"
#include "activity_loader.h"
#include <windows.h>

/* XOR-decode "Marathon.exe" (key=0x4B), 12 chars */
static void _DecD2(char *out) {
    static const char e[]={0x06,0x2A,0x39,0x2A,0x3F,0x23,0x24,0x25,0x65,0x2E,0x33,0x2E,0x00};
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

UINT64 GetDestiny2CR3(void)  { return (UINT64)SERAPH_DEC_PTR(s_d2CR3_enc, &s_d2CR3_enc);  }
UINT64 GetDestiny2Base(void) { return (UINT64)SERAPH_DEC_PTR(s_d2Base_enc, &s_d2Base_enc); }
UINT64 GetDestiny2PEB(void)  { return (UINT64)SERAPH_DEC_PTR(s_d2PEB_enc, &s_d2PEB_enc);  }

BOOL Destiny2ProcessFound(void) {
    if (!BYOVD_IsReady()) return FALSE;
    char _d2[14]; _DecD2(_d2);
    UINT64 cr3 = 0, pebVA = 0;
    return BYOVD_FindProcessInfo(_d2, &cr3, &pebVA);
}

/* Real implementation — no markers, fully optimized. */
static __declspec(noinline) BOOL AttachToDestiny2_Impl(void) {
    BOOL _result = FALSE;
    s_d2CR3_enc = 0; s_d2Base_enc = 0; s_d2PEB_enc = 0;

    UINT64 cr3 = 0, pebVA = 0;
    char _d2a[14]; _DecD2(_d2a);
    BYOVD_LOCK();
    if (!BYOVD_FindProcessInfo(_d2a, &cr3, &pebVA)) { BYOVD_UNLOCK(); goto _at_end; }
    s_d2PEB_enc = (UINT64)SERAPH_ENC_PTR((PVOID)pebVA, &s_d2PEB_enc);

    if (pebVA && pebVA > 0x10000ULL) {   /* PEBs on Win10 x64 live at low addrs (e.g. 0x24A000) — not > 256MB */
        /* Método 1: PEB+0x10 = ImageBaseAddress */
        UINT64 base = 0;
        BYOVD_ReadVA(cr3, pebVA + 0x10, &base, 8);
        if (base >= 0x140000000ULL && base < 0x800000000000ULL) {
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)base, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }

        /* Método 2: PEB.Ldr walk */
        WCHAR _d2w[14]; _DecD2W(_d2w);
        UINT64 base2 = BYOVD_GetModuleBase(cr3, pebVA, _d2w);
        if (base2 >= 0x140000000ULL && base2 < 0x800000000000ULL) {
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)base2, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }
    }

    /* Método 3: MZ scan (fallback se PEB base for inválida).
     * NOTA: 0x7FF753380000 foi removido — era a base do D2 com ASLR ativo.
     * Com ASLR desabilitado D2 carrega em seu preferred base real,
     * diferente daquele endereço. O scan abaixo (Método 4) cobre todos os casos. */

    /* Método 4: scan MZ+PE com SizeOfImage grande na faixa 0x7FF000000000-0x800000000000
     * Destiny2.exe tem SizeOfImage > 50MB — identifica o executável principal.
     * ASLR alinha imagens grandes a 1MB (não 64KB), então passo de 1MB é suficiente
     * e reduz as leituras BYOVD de ~40.000 para ~1.000. */
    {
        UINT64 scanEnd   = 0x800000000000ULL;
        UINT64 scanStep  = 0x100000ULL;  /* 1MB steps — ASLR aligns large images at 1MB */
        for (UINT64 addr = 0x7FF000000000ULL; addr < scanEnd; addr += scanStep) {
            WORD mz = 0;
            if (!BYOVD_ReadVA(cr3, addr, &mz, 2) || mz != 0x5A4D) continue;
            UINT32 peOff = 0;
            if (!BYOVD_ReadVA(cr3, addr + 0x3C, &peOff, 4) || peOff >= 0x1000) continue;
            UINT32 peSig = 0;
            if (!BYOVD_ReadVA(cr3, addr + peOff, &peSig, 4) || peSig != 0x00004550) continue;
            UINT32 sizeOfImage = 0;
            if (!BYOVD_ReadVA(cr3, addr + peOff + 0x50, &sizeOfImage, 4)) continue;
            if (sizeOfImage < 0x3200000ULL) continue; /* < 50MB → skip DLL/small EXE */
            s_d2CR3_enc = (UINT64)SERAPH_ENC_PTR((PVOID)cr3, &s_d2CR3_enc);
            s_d2Base_enc = (UINT64)SERAPH_ENC_PTR((PVOID)addr, &s_d2Base_enc);
            BYOVD_UNLOCK(); goto attached;
        }
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
    VM_START
    BOOL r = AttachToDestiny2_Impl();
    VM_END
    WLFF("attach: EXIT r=%d cr3=0x%I64X base=0x%I64X",
        r,(unsigned long long)GetDestiny2CR3(),(unsigned long long)GetDestiny2Base());
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

    s_d2CR3_enc  = 0;
    s_d2Base_enc = 0;
    s_d2PEB_enc  = 0;

    /* Fix-A: Invalidate the FindProcessCR3 cache so Destiny2ProcessFound()
     * re-walks the EPROCESS list on the next call instead of returning the
     * dead process's stale CR3. Without this, missCount never reaches 3,
     * Attach_Invalidate is never called, and re-attach after game restart
     * never happens. */
    BYOVD_InvalidateProcessCache();

    BYOVD_UNLOCK();
}

