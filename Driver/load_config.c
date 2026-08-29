#include <ntddk.h>
/* Load configuration directory is provided by the WDK toolset for kernel drivers.
 * The custom _load_config_used definition was removed because it used an
 * incomplete IMAGE_LOAD_CONFIG_DIRECTORY64 struct (missing extended fields added
 * in newer WDK versions) causing LNK1329. The toolset injects the correct struct. */

/* Security cookie extern for WDK compat */
extern ULONG_PTR __security_cookie;
void __stdcall __security_check_cookie(ULONG_PTR cookie) { (void)cookie; }
