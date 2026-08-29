/*
 * shadow_mem.c — MmCopyVirtualMemory inline hook for scan spoofing
 *
 * Strategy:
 *   1. Loader creates a named Global section containing a SHADOW_TABLE of patches.
 *   2. Driver maps that section in kernel space.
 *   3. Driver installs a 14-byte absolute-JMP hook on MmCopyVirtualMemory.
 *   4. Hook handler: calls original, then if source=D2 and buffer overlaps a
 *      registered patch, overwrites the target buffer with original bytes.
 *   5. BattlEye's ReadProcessMemory calls MmCopyVirtualMemory internally and
 *      therefore always sees the unpatched bytes.
 *
 * Target: Win10 22H2 x64, no HVCI.
 */

#include "shadow_mem.h"
#include "debug_kernel.h"  /* DEBUG_PRINT macros */
#ifndef DBG_PRINT
#  define DBG_PRINT DbgPrint  /* raw kernel debug output */
#endif
#include <intrin.h>
/* Kernel types not pulled in through shadow_mem.h on some WDK configurations */
#ifndef _KAPC_STATE_DEFINED
#define _KAPC_STATE_DEFINED
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE;
#endif
#ifndef _KAPC_STACK_DECLARED
#define _KAPC_STACK_DECLARED
NTKERNELAPI VOID KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE, PEPROCESS*);
#endif

/* ── ZwMapViewOfSection / ZwUnmapViewOfSection — needed in kernel context ── */
NTSYSAPI NTSTATUS NTAPI ZwOpenSection(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);

/* ── Global hook state pointer ─────────────────────────────────────────────── */
static SHADOW_CTX* g_SCtx = NULL;

/* ── MmCopyVirtualMemory function type ─────────────────────────────────────── */
typedef NTSTATUS (NTAPI *FnMmCopy)(
    PEPROCESS SrcProc, PVOID SrcAddr,
    PEPROCESS DstProc, PVOID DstAddr,
    SIZE_T    Size,
    KPROCESSOR_MODE Mode,
    PSIZE_T   RetSize);

/* ════════════════════════════════════════════════════════════════════════════
   CR0.WP manipulation — used only during the brief hook install / removal.
   IRQL raised to DPC so we are not preempted on this CPU while WP is off.
   Other CPUs: the 14-byte memcpy is fast enough that the window is negligible.
   ══════════════════════════════════════════════════════════════════════════ */
static KIRQL s_wpIrql;

static FORCEINLINE void WP_Off(void) {
    s_wpIrql = KeRaiseIrqlToDpcLevel();
    __writecr0(__readcr0() & ~(1ULL << 16));
    _mm_sfence();
}

static FORCEINLINE void WP_On(void) {
    _mm_sfence();
    __writecr0(__readcr0() | (1ULL << 16));
    KeLowerIrql(s_wpIrql);
}

/* ════════════════════════════════════════════════════════════════════════════
   RIP-relative instruction detector.
   Scans the first `len` bytes for any instruction whose encoding uses a
   RIP-relative displacement.  If found, we cannot safely build a trampoline
   from those bytes without fixing up the displacement (complex) — so we
   bail and leave the hook uninstalled (graceful degradation).

   Checked opcodes:
     E8          — CALL rel32
     E9          — JMP  rel32
     0F 8x       — Jcc  rel32
     [REX] 8B/8D/89 ModRM(mod=0 rm=5) — MOV r/m,[RIP+d32] or similar
   ══════════════════════════════════════════════════════════════════════════ */
static BOOLEAN HasRipRelative(const UCHAR* b, ULONG len) {
    for (ULONG i = 0; i < len; i++) {
        /* Skip REX prefix — record and continue */
        BOOLEAN rex = (b[i] >= 0x40 && b[i] <= 0x4F);
        ULONG   op  = rex ? i + 1 : i;
        if (op >= len) break;

        if (b[op] == 0xE8 || b[op] == 0xE9) return TRUE;    /* CALL/JMP rel32 */
        if (b[op] == 0x0F && op + 1 < len &&
            (b[op+1] & 0xF0) == 0x80) return TRUE;           /* Jcc rel32      */

        /* MOV/LEA with ModRM: mod=00 rm=101 = [RIP+d32] */
        if ((b[op] == 0x8B || b[op] == 0x8D || b[op] == 0x89) &&
            op + 1 < len && (b[op+1] & 0xC7) == 0x05) return TRUE;

        /* Advance by 1; a full disassembler would advance by insn length,
           but false positives here just mean we skip installation safely. */
    }
    return FALSE;
}

/* ════════════════════════════════════════════════════════════════════════════
   Section name: derived from C: volume serial — MUST match loader algorithm.
   Reads volume serial via ZwCreateFile(\Device\HarddiskVolume*) + ZwQueryVolume.
   Fallback: read from registry (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion).
   ══════════════════════════════════════════════════════════════════════════ */
NTSYSAPI NTSTATUS NTAPI ZwQueryVolumeInformationFile(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FS_INFORMATION_CLASS);

static ULONG GetVolumeSerialKernel(void) {
    /* Open \??\C: */
    UNICODE_STRING volPath;
    RtlInitUnicodeString(&volPath, L"\\??\\C:");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &volPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hVol = NULL;
    IO_STATUS_BLOCK iosb = {0};
    NTSTATUS st = ZwCreateFile(&hVol, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &oa, &iosb,
        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st) || !hVol) return 0;
    /* FileFsVolumeInformation = 1 */
    struct { LARGE_INTEGER VolumeCreationTime; ULONG VolumeSerialNumber; ULONG VolumeLabelLength; BOOLEAN SupportsObjects; WCHAR VolumeLabel[1]; } volInfo = {0};
    st = ZwQueryVolumeInformationFile(hVol, &iosb, &volInfo, sizeof(volInfo), 1/*FileFsVolumeInformation*/);
    ZwClose(hVol);
    if (!NT_SUCCESS(st)) { DBG_PRINT("[DRV] GetVolumeSerialKernel: ZwQueryVolumeInformation FAILED st=0x%08X\n", st); return 0; }
    DBG_PRINT("[DRV] GetVolumeSerialKernel: vol serial = 0x%08X\n", volInfo.VolumeSerialNumber);
    return volInfo.VolumeSerialNumber;
}

static void DecodeSectionName(WCHAR* out, ULONG outChars) {
    ULONG vol = GetVolumeSerialKernel();
    /* Same hash as loader — MUST match exactly */
    ULONG h1 = vol * 0x9E3779B9u;
    h1 = (h1 << 13) | (h1 >> 19);
    h1 ^= 0xA5C3E1F7u;
    ULONG h2 = h1 * 0x85EBCA6Bu;
    h2 = (h2 << 7) | (h2 >> 25);
    /* Build: \BaseNamedObjects\Global\{XXXXXXXX-XXXX} */
    /* Format manually — no swprintf in kernel without ntstrsafe */
    static const WCHAR prefix[] = L"\\BaseNamedObjects\\Global\\{";
    static const WCHAR hexChars[] = L"0123456789ABCDEF";
    ULONG pos = 0;
    for (ULONG i = 0; prefix[i] && pos + 1 < outChars; i++) out[pos++] = prefix[i];
    /* h1 as 8 hex chars */
    for (int i = 7; i >= 0 && pos + 1 < outChars; i--) out[pos++] = hexChars[(h1 >> (i*4)) & 0xF];
    if (pos + 1 < outChars) out[pos++] = L'-';
    /* h2 low 16 bits as 4 hex chars */
    USHORT h2w = (USHORT)(h2 & 0xFFFF);
    for (int i = 3; i >= 0 && pos + 1 < outChars; i--) out[pos++] = hexChars[(h2w >> (i*4)) & 0xF];
    if (pos + 1 < outChars) out[pos++] = L'}';
    out[pos] = 0;
    DBG_PRINT("[DRV] DecodeSectionName: vol=0x%08X h1=0x%08X h2=0x%08X name=%ws\n", vol, h1, h2, out);
}

/* ════════════════════════════════════════════════════════════════════════════
   THE HOOK HANDLER
   Called in place of MmCopyVirtualMemory for every cross-process read.
   ══════════════════════════════════════════════════════════════════════════ */
NTSTATUS NTAPI ShadowHook_MmCopyVirtualMemory(
    PEPROCESS SrcProc, PVOID SrcAddr,
    PEPROCESS DstProc, PVOID DstAddr,
    SIZE_T    Size,
    KPROCESSOR_MODE Mode,
    PSIZE_T   RetSize)
{
    SHADOW_CTX* ctx = g_SCtx;

    /* Always call the original via trampoline first */
    if (!ctx || !ctx->trampolineBuf) return STATUS_UNSUCCESSFUL;

    InterlockedIncrement(&ctx->hookRefCount);

    FnMmCopy orig = (FnMmCopy)(PVOID)ctx->trampolineBuf;
    NTSTATUS st   = orig(SrcProc, SrcAddr, DstProc, DstAddr, Size, Mode, RetSize);

    /* Only spoof if: hook active, source is D2, copy succeeded */
    if (!NT_SUCCESS(st)          ||
        !ctx->hookInstalled      ||
        !ctx->d2Process          ||
        SrcProc != ctx->d2Process||
        !DstProc || !DstAddr     ||
        Size == 0) {
        InterlockedDecrement(&ctx->hookRefCount);
        return st;
    }

    SHADOW_TABLE* tbl = ctx->table;
    if (!tbl || tbl->magic != SHADOW_TABLE_MAGIC) {
        InterlockedDecrement(&ctx->hookRefCount);
        return st;
    }

    /* ── Collect overlapping patches under the table's CAS spinlock ── */
    /* We use a simple struct on the stack — max 64 entries × 80 bytes = 5120 B.
       This is within the kernel stack limit (24 KB on x64 Win10). */
    typedef struct { ULONG64 va; ULONG sz; UCHAR orig[SHADOW_MAX_BYTES]; } LP;
    LP     local[SHADOW_MAX_ENTRIES];
    ULONG  lcnt = 0;

    /* Acquire table lock (busy-wait; no IRQL change — lock is just an atomic flag) */
    while (InterlockedCompareExchange(&tbl->lock, 1L, 0L) != 0L)
        YieldProcessor();

    ULONG64 srcStart = (ULONG64)(ULONG_PTR)SrcAddr;
    ULONG64 srcEnd   = srcStart + (ULONG64)Size;

    for (ULONG i = 0; i < SHADOW_MAX_ENTRIES && lcnt < SHADOW_MAX_ENTRIES; i++) {
        volatile SHADOW_ENTRY* e = &tbl->entries[i];
        if (!e->active) continue;

        ULONG64 ps = e->d2va;
        ULONG64 pe = ps + (ULONG64)e->size;

        if (ps < srcEnd && pe > srcStart) {
            /* BUGFIX: bound e->size before copy -- corrupted shared section
             * with e->size > SHADOW_MAX_BYTES overflows local[] on kernel
             * stack -> stack corruption -> BSOD. */
            ULONG csz = e->size;
            if (csz == 0 || csz > SHADOW_MAX_BYTES) continue;
            local[lcnt].va = ps;
            local[lcnt].sz = csz;
            RtlCopyMemory(local[lcnt].orig, (const void*)e->original, csz);
            lcnt++;
        }
    }

    InterlockedExchange(&tbl->lock, 0L);

    if (lcnt == 0) {
        InterlockedDecrement(&ctx->hookRefCount);
        return st;
    }

    /* ── Attach to destination process and substitute original bytes ── */
    /* KeStackAttachProcess requires IRQL <= APC_LEVEL.
       We are at PASSIVE_LEVEL here (called via user ReadProcessMemory → syscall). */
    KAPC_STATE apc;
    KeStackAttachProcess(DstProc, &apc);

    __try {
        for (ULONG i = 0; i < lcnt; i++) {
            ULONG64 ps    = local[i].va;
            ULONG64 pe    = ps + (ULONG64)local[i].sz;
            ULONG64 start = (ps > srcStart) ? ps : srcStart;
            ULONG64 end   = (pe < srcEnd)   ? pe : srcEnd;
            if (start >= end) continue;

            SIZE_T dstOff  = (SIZE_T)(start - srcStart); /* offset in target buf */
            SIZE_T origOff = (SIZE_T)(start - ps);       /* offset in orig bytes  */
            SIZE_T cpyLen  = (SIZE_T)(end   - start);

            PUCHAR dst = (PUCHAR)DstAddr + dstOff;
            ProbeForWrite(dst, cpyLen, 1);
            RtlCopyMemory(dst, local[i].orig + origOff, cpyLen);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Target buffer may have been freed or remapped — ignore silently */
    }

    KeUnstackDetachProcess(&apc);

    InterlockedDecrement(&ctx->hookRefCount);
    return st;
}

/* ════════════════════════════════════════════════════════════════════════════
   Build the 28-byte trampoline in NonPagedPool:
     [0..13]  — saved original bytes of MmCopyVirtualMemory
     [14..19] — FF 25 00 00 00 00  (JMP [RIP+0])
     [20..27] — address of MmCopyVirtualMemory+14
   ══════════════════════════════════════════════════════════════════════════ */
static NTSTATUS BuildTrampoline(SHADOW_CTX* ctx) {
#pragma warning(suppress:4996)
    ctx->trampolineBuf = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPool,   /* executable on Win10 without HVCI */
        28,
        'fTrS');
    if (!ctx->trampolineBuf) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(ctx->trampolineBuf, ctx->savedBytes, 14);

    PUCHAR jmp = ctx->trampolineBuf + 14;
    jmp[0] = 0xFF; jmp[1] = 0x25;
    *(ULONG*)  (jmp + 2) = 0x00000000;                         /* disp = 0 (RIP+0) */
    *(ULONG64*)(jmp + 6) = (ULONG64)ctx->fnMmCopy + 14;       /* continue after hook */

    return STATUS_SUCCESS;
}

/* WriteHook14: write 14 bytes atomically (as two 8-byte stores) under CR0.WP=0.
 * A plain 14-byte RtlCopyMemory is NOT atomic: another CPU running MmCopyVirtualMemory
 * can observe a torn state after we write the first 6 bytes (0xFF 0x25 ...) but before
 * the remaining 8 (the target address). The torn bytes form a valid but WRONG JMP and
 * crash D2 or the system. Fix: write bytes [6..13] first, then bytes [0..5] (the JMP
 * opcode). Any CPU that sees only the second write still sees the original prologue;
 * any CPU that sees both writes sees a complete JMP. */
static void WriteBytes(PVOID target, const void* src, ULONG len) {
    WP_Off();
    if (len == 14) {
        /* Store tail first (8 bytes: JMP target address), then head (6 bytes: opcode).
         * Both stores are naturally 8-byte aligned on the PTE boundary and atomic. */
        ULONG64 tail; RtlCopyMemory(&tail, (const UCHAR*)src + 6, 8);
        InterlockedExchange64((LONG64*)((UCHAR*)target + 6), (LONG64)tail);
        _mm_sfence();
        /* Write first 8 bytes (overlapping: bytes 0-7 cover the 6-byte opcode + 2 of address) */
        ULONG64 head; RtlCopyMemory(&head, src, 8);
        InterlockedExchange64((LONG64*)target, (LONG64)head);
    } else {
        RtlCopyMemory(target, src, len);
    }
    WP_On();
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowMem_Init — called from DriverEntry (or worker thread).
   Opens the named section the loader created, maps it, installs the hook.
   ══════════════════════════════════════════════════════════════════════════ */
NTSTATUS ShadowMem_Init(SHADOW_CTX* ctx) {
    if (!ctx) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(ctx, sizeof(*ctx));
    g_SCtx = ctx;

    /* ── 1. Locate MmCopyVirtualMemory ── */
    UNICODE_STRING fnName;
    RtlInitUnicodeString(&fnName, L"MmCopyVirtualMemory");
    ctx->fnMmCopy = MmGetSystemRoutineAddress(&fnName);
    if (!ctx->fnMmCopy) return STATUS_NOT_FOUND;

    /* ── 2. Open the named section created by the loader ── */
    WCHAR nameBuf[48];
    DecodeSectionName(nameBuf, 48);

    UNICODE_STRING secName;
    RtlInitUnicodeString(&secName, nameBuf);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &secName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    /* Retry for up to 5 s — loader may not have created the section yet */
    NTSTATUS s = STATUS_NOT_FOUND;
    for (int retry = 0; retry < 50; retry++) {
        s = ZwOpenSection(&ctx->sectionHandle,
            SECTION_MAP_READ | SECTION_MAP_WRITE, &oa);
        if (NT_SUCCESS(s)) break;
        LARGE_INTEGER d; d.QuadPart = -1000000LL; /* 100 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &d);
    }
    if (!NT_SUCCESS(s)) return s;

    /* ── 3. Map section into kernel VA space ── */
    SIZE_T viewSize = SHADOW_SECTION_SIZE;
    s = ZwMapViewOfSection(ctx->sectionHandle, NtCurrentProcess(),
        &ctx->sectionKva, 0, 0, NULL, &viewSize,
        ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(s)) {
        ZwClose(ctx->sectionHandle); ctx->sectionHandle = NULL;
        return s;
    }
    ctx->table = (SHADOW_TABLE*)ctx->sectionKva;

    if (ctx->table->magic != SHADOW_TABLE_MAGIC) {
        ZwUnmapViewOfSection(NtCurrentProcess(), ctx->sectionKva);
        ctx->sectionKva = NULL; ctx->table = NULL;
        ZwClose(ctx->sectionHandle); ctx->sectionHandle = NULL;
        return STATUS_INVALID_PARAMETER;
    }

    /* ── 4. Save first 14 bytes and check for RIP-relative encodings ── */
    RtlCopyMemory(ctx->savedBytes, ctx->fnMmCopy, 14);
    if (HasRipRelative(ctx->savedBytes, 14)) {
        /* Cannot build a safe trampoline — hook skipped (graceful degradation) */
        ctx->initialized = TRUE;
        return STATUS_SUCCESS;
    }

    /* ── 5. Allocate trampoline and install hook ── */
    s = BuildTrampoline(ctx);
    if (!NT_SUCCESS(s)) {
        ZwUnmapViewOfSection(NtCurrentProcess(), ctx->sectionKva);
        ctx->sectionKva = NULL; ctx->table = NULL;
        ZwClose(ctx->sectionHandle); ctx->sectionHandle = NULL;
        return s;
    }

    /* Build hook bytes: JMP [RIP+0] → ShadowHook_MmCopyVirtualMemory */
    UCHAR hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(ULONG64*)(hook + 6) = (ULONG64)ShadowHook_MmCopyVirtualMemory;

    WriteBytes(ctx->fnMmCopy, hook, 14);

    ctx->hookInstalled = TRUE;
    ctx->initialized   = TRUE;
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowMem_UpdateD2Process — call periodically (e.g. from worker tick)
   to refresh the cached EPROCESS pointer when D2 PID changes.
   ══════════════════════════════════════════════════════════════════════════ */
VOID ShadowMem_UpdateD2Process(SHADOW_CTX* ctx) {
    if (!ctx || !ctx->table) return;

    ULONG pid = ctx->table->d2pid;
    if (!pid) {
        /* PID cleared — D2 exited */
        PEPROCESS old = (PEPROCESS)InterlockedExchangePointer(
            (PVOID*)&ctx->d2Process, NULL);
        if (old) ObDereferenceObject(old);
        return;
    }

    /* Only re-lookup if PID actually changed */
    if (ctx->d2Process) {
        HANDLE cur = PsGetProcessId(ctx->d2Process);
        if ((ULONG)(ULONG_PTR)cur == pid) return; /* same process — no change */
        PEPROCESS old = (PEPROCESS)InterlockedExchangePointer(
            (PVOID*)&ctx->d2Process, NULL);
        if (old) ObDereferenceObject(old);
    }

    PEPROCESS proc = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) {
        InterlockedExchangePointer((PVOID*)&ctx->d2Process, proc);
        /* Note: reference held until Deinit or next update */
    }
}

/* ════════════════════════════════════════════════════════════════════════════
   ShadowMem_Deinit — called from DriverUnload.
   Removes hook, waits for all executing handlers to return, then frees resources.
   ══════════════════════════════════════════════════════════════════════════ */
VOID ShadowMem_Deinit(SHADOW_CTX* ctx) {
    if (!ctx) return;

    if (ctx->hookInstalled) {
        ctx->hookInstalled = FALSE;
        KeMemoryBarrier();
        /* Restore original bytes */
        WriteBytes(ctx->fnMmCopy, ctx->savedBytes, 14);
        KeMemoryBarrier();
        /* Mandatory delay: let any CPU that decoded the JMP but hasn't yet
         * incremented hookRefCount finish entering the handler. */
        LARGE_INTEGER settle; settle.QuadPart = -500000LL; /* 50 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &settle);
        /* Spin until all in-flight handlers exit */
        LARGE_INTEGER d; d.QuadPart = -100000LL; /* 10 ms */
        while (InterlockedCompareExchange(&ctx->hookRefCount, 0L, 0L) != 0L)
            KeDelayExecutionThread(KernelMode, FALSE, &d);
    }

    if (ctx->trampolineBuf) {
        ExFreePool(ctx->trampolineBuf);
        ctx->trampolineBuf = NULL;
    }
    if (ctx->sectionKva) {
        ZwUnmapViewOfSection(NtCurrentProcess(), ctx->sectionKva);
        ctx->sectionKva = NULL;
        ctx->table      = NULL;
    }
    if (ctx->sectionHandle) {
        ZwClose(ctx->sectionHandle);
        ctx->sectionHandle = NULL;
    }
    if (ctx->d2Process) {
        ObDereferenceObject(ctx->d2Process);
        ctx->d2Process = NULL;
    }

    g_SCtx = NULL;
}
