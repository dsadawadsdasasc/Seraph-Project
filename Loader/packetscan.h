#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void PacketScan_Init(void);
void PacketScan_Tick(void);
void PacketScan_Shutdown(void);

#ifdef __cplusplus
}
#endif
