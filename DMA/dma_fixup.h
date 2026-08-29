#pragma once

#include <windows.h>



#ifdef __cplusplus

extern "C" {

#endif



BOOL DmaDumpMemoryMap(void);

BOOL DmaEnsureMemoryMap(void);

BOOL DmaSetFPGA(void *vmmHandle);



#ifdef __cplusplus

}

#endif

