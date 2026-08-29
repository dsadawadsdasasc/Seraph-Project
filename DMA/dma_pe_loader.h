#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* HMEMORYMODULE;

HMEMORYMODULE DmaLoadPE(const void* peData, size_t peSize);
FARPROC DmaGetPEProcAddress(HMEMORYMODULE module, const char* name);
void DmaFreePE(HMEMORYMODULE module);

#ifdef __cplusplus
}
#endif
