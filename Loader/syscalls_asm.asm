; syscalls_asm.asm -- Indirect syscall stubs (P5.1 + Phase 1 expansion).
; Win10/11 x64, assembled with ml64.exe.
;
; Convention P5.1: mov r10,rcx ; mov eax,[ssn] ; jmp [g_SyscallGadgetVA]
;   The gadget points at `syscall; ret` inside ntdll.dll.
;   Stack walks see RIP in ntdll (legitimate). The `ret` in the gadget
;   returns to the original caller (we used `jmp`, not `call`).
;
; win32k syscalls (NtUser*) use SSN in the 0x1000+ range.
;   The same gadget and trampoline work — the CPU dispatches to win32k.sys
;   based on the SSN alone; RIP still appears in ntdll from the stack walk.
;
; FALLBACK: if g_SyscallGadgetVA==0, trampoline falls back to direct syscall.

EXTERN g_SyscallGadgetVA:QWORD

; ── Existing ntoskrnl syscall numbers ──────────────────────────────────────
EXTERN g_NtLoadDriverSyscall:DWORD
EXTERN g_NtUnloadDriverSyscall:DWORD
EXTERN g_NtQuerySystemInformationSyscall:DWORD
EXTERN g_NtOpenProcessSyscall:DWORD
EXTERN g_NtQueryInformationProcessSyscall:DWORD
EXTERN g_SysNtOpenFileSyscall:DWORD
EXTERN g_SysNtDeviceIoControlFileSyscall:DWORD
EXTERN g_SysNtCloseSyscall:DWORD
EXTERN g_SysNtMapViewOfSectionSyscall:DWORD
EXTERN g_SysNtUnmapViewOfSectionSyscall:DWORD
EXTERN g_SysNtDuplicateObjectSyscall:DWORD
EXTERN g_SysNtGetContextThreadSyscall:DWORD

; ── New ntoskrnl syscall numbers (Phase 1) ─────────────────────────────────
EXTERN g_SysNtCreateThreadExSyscall:DWORD
EXTERN g_SysNtAllocateVirtualMemorySyscall:DWORD
EXTERN g_SysNtProtectVirtualMemorySyscall:DWORD
EXTERN g_SysNtFreeVirtualMemorySyscall:DWORD
EXTERN g_SysNtDelayExecutionSyscall:DWORD
EXTERN g_SysNtTerminateProcessSyscall:DWORD
EXTERN g_SysNtOpenProcessTokenSyscall:DWORD
EXTERN g_SysNtAdjustPrivilegesTokenSyscall:DWORD


; ── win32k syscall numbers — extracted from win32u.dll (Phase 1) ───────────
EXTERN g_SysNtUserSendInputSyscall:DWORD
EXTERN g_SysNtUserGetAsyncKeyStateSyscall:DWORD

.CODE

; ==== Central indirect-syscall trampoline ==================================
; Caller has already set r10=rcx and eax=[ssn]. Jump here to fire syscall
; via ntdll gadget (`syscall; ret` at g_SyscallGadgetVA) so that stack
; walks see a legitimate RIP inside ntdll, not our .text section.
_seraph_syscall_via_gadget PROC
    mov r11, QWORD PTR [g_SyscallGadgetVA]
    test r11, r11
    jz   _direct_sc
    jmp r11                     ; gadget = `syscall; ret` inside ntdll
_direct_sc:
    syscall                     ; fallback: direct (g_SyscallGadgetVA not set)
    ret
_seraph_syscall_via_gadget ENDP

; ========================================================================
; Existing ntoskrnl stubs
; ========================================================================

SysNtLoadDriver PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtLoadDriverSyscall]
    jmp _seraph_syscall_via_gadget
SysNtLoadDriver ENDP

SysNtUnloadDriver PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtUnloadDriverSyscall]
    jmp _seraph_syscall_via_gadget
SysNtUnloadDriver ENDP

SysNtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtQuerySystemInformationSyscall]
    jmp _seraph_syscall_via_gadget
SysNtQuerySystemInformation ENDP

SysNtOpenProcess PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtOpenProcessSyscall]
    jmp _seraph_syscall_via_gadget
SysNtOpenProcess ENDP

SysNtQueryInformationProcess PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtQueryInformationProcessSyscall]
    jmp _seraph_syscall_via_gadget
SysNtQueryInformationProcess ENDP

SysNtOpenFile PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtOpenFileSyscall]
    jmp _seraph_syscall_via_gadget
SysNtOpenFile ENDP

SysNtDeviceIoControlFile PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtDeviceIoControlFileSyscall]
    jmp _seraph_syscall_via_gadget
SysNtDeviceIoControlFile ENDP

SysNtClose PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtCloseSyscall]
    jmp _seraph_syscall_via_gadget
SysNtClose ENDP

SysNtMapViewOfSection PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtMapViewOfSectionSyscall]
    jmp _seraph_syscall_via_gadget
SysNtMapViewOfSection ENDP

SysNtUnmapViewOfSection PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtUnmapViewOfSectionSyscall]
    jmp _seraph_syscall_via_gadget
SysNtUnmapViewOfSection ENDP

SysNtDuplicateObject PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtDuplicateObjectSyscall]
    jmp _seraph_syscall_via_gadget
SysNtDuplicateObject ENDP

SysNtGetContextThread PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtGetContextThreadSyscall]
    jmp _seraph_syscall_via_gadget
SysNtGetContextThread ENDP

; ========================================================================
; New ntoskrnl stubs (Phase 1)
; ========================================================================

SysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtCreateThreadExSyscall]
    jmp _seraph_syscall_via_gadget
SysNtCreateThreadEx ENDP

SysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtAllocateVirtualMemorySyscall]
    jmp _seraph_syscall_via_gadget
SysNtAllocateVirtualMemory ENDP

SysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtProtectVirtualMemorySyscall]
    jmp _seraph_syscall_via_gadget
SysNtProtectVirtualMemory ENDP

SysNtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtFreeVirtualMemorySyscall]
    jmp _seraph_syscall_via_gadget
SysNtFreeVirtualMemory ENDP

SysNtDelayExecution PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtDelayExecutionSyscall]
    jmp _seraph_syscall_via_gadget
SysNtDelayExecution ENDP

SysNtTerminateProcess PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtTerminateProcessSyscall]
    jmp _seraph_syscall_via_gadget
SysNtTerminateProcess ENDP

SysNtOpenProcessToken PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtOpenProcessTokenSyscall]
    jmp _seraph_syscall_via_gadget
SysNtOpenProcessToken ENDP

SysNtAdjustPrivilegesToken PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtAdjustPrivilegesTokenSyscall]
    jmp _seraph_syscall_via_gadget
SysNtAdjustPrivilegesToken ENDP


; ========================================================================
; win32k stubs — NtUserSendInput, NtUserGetAsyncKeyState (Phase 1)
; SSN is in 0x1000+ range (win32k SSDT). Same trampoline, same gadget.
; ========================================================================

; Renamed to _asm so syscalls.c C-wrappers provide the public symbol with
; a user32 fallback when SSN == 0 (e.g. win32k stub parse failed on Win11).
SysNtUserSendInput_asm PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtUserSendInputSyscall]
    jmp _seraph_syscall_via_gadget
SysNtUserSendInput_asm ENDP

SysNtUserGetAsyncKeyState_asm PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_SysNtUserGetAsyncKeyStateSyscall]
    jmp _seraph_syscall_via_gadget
SysNtUserGetAsyncKeyState_asm ENDP

END
