/* Minimal test driver — DriverEntry only returns SUCCESS */
#include <ntddk.h>

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT dO) { (void)dO; }

NTSTATUS DriverEntry(PDRIVER_OBJECT dO, PUNICODE_STRING rP) {
    (void)rP;
    dO->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
