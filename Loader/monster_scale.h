#ifndef MONSTER_SCALE_H
#define MONSTER_SCALE_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MONSTER_SCALE_DEFAULT 5 /* 5 / 5.0f = 1.0f normal size */

/* Enable / Disable Monster Scale feature */
void MonsterScale_SetEnabled(BOOL enable);
BOOL MonsterScale_IsEnabled(void);

/* Set target scale integer (-10 to 10 -> -2.0f to 2.0f) */
void MonsterScale_SetVal(int val);
int  MonsterScale_GetVal(void);

/* Reset to default size 1.0f (val = 5) */
void MonsterScale_Reset(void);

/* Tick function called from background update loop */
void MonsterScale_Tick(void);

#ifdef __cplusplus
}
#endif

#endif /* MONSTER_SCALE_H */
