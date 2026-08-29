#pragma once
#include <windows.h>

#ifdef SERAPH_DMA_BUILD

#ifdef __cplusplus
extern "C" {
#endif

/* 0 = off, 1 = KmBox Net, 2 = KmBox B+ (serial) */
#define SERAPH_KMBOX_OFF    0
#define SERAPH_KMBOX_NET    1
#define SERAPH_KMBOX_BPLUS  2

typedef struct SeraphKmboxSettings {
    int  device_type;     /* SERAPH_KMBOX_* */
    int  hw_aim;         /* use KmBox for aimbot when connected */
    int  auto_connect;
    char ip[32];
    char port[16];
    char uuid[64];
    char com_port[32];
    char baud_str[16];
} SeraphKmboxSettings;

SeraphKmboxSettings *SeraphKmbox_GetSettings(void);

/* Throttled (5s) — call from main menu loop only, not every overlay frame. */
void SeraphKmbox_AutoConnect(void);

BOOL SeraphKmbox_IsReady(void);     /* hw_aim ON + connected — for aimbot use */
BOOL SeraphKmbox_IsConnected(void); /* connected regardless of hw_aim — for UI */
void SeraphKmbox_Connect(void);
void SeraphKmbox_Disconnect(void);

/* Rate-limited mouse output (~144 Hz). Falls back to no-op if not ready. */
void SeraphKmbox_MoveAccum(int dx, int dy);
void SeraphKmbox_LeftClick(int isdown);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_DMA_BUILD */
