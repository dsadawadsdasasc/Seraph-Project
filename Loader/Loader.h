#pragma once
#include <Windows.h>
#include <winternl.h>
#include "shared.h"
#include "ThemidaSDK.h"
#ifdef __cplusplus
extern "C" {
#endif
    /* NT driver load/unload — used by byovd.c via dynamic GetProcAddress */
    NTSYSCALLAPI NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING);
    NTSYSCALLAPI NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING);
#ifdef __cplusplus
}
#endif
#include "XorStr.h"
