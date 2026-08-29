#pragma once
#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL   Destiny2ProcessFound(void);
BOOL   AttachToDestiny2(void);
UINT64 GetDestiny2CR3(void);
UINT64 GetDestiny2Base(void);
UINT64 GetDestiny2PEB(void);
void   Attach_Invalidate(void);  /* zera CR3/base quando jogo fecha */

#ifdef __cplusplus
}
#endif