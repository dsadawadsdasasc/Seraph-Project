#ifndef OPK_H
#define OPK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SERAPH_EXCLUDE_OPK
void OPK_SetEnabled(BOOL state);
BOOL OPK_IsEnabled(void);
void OPK_SetDistance(int value);
int  OPK_GetDistance(void);

void OPK_Tick(void);
#else
static inline void OPK_SetEnabled(BOOL state) { (void)state; }
static inline BOOL OPK_IsEnabled(void) { return FALSE; }
static inline void OPK_SetDistance(int value) { (void)value; }
static inline int  OPK_GetDistance(void) { return 0; }
static inline void OPK_Tick(void) {}
#endif

#ifdef __cplusplus
}
#endif

#endif /* OPK_H */
