#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "shared.h"
VOID KeInitializeEvasion(PEVASION_CONTEXT);
BOOLEAN CheckSandbox();
