/*
 * themida_stubs.c — No-op IAT overrides for Themida SecureEngine SDK.
 *
 * SecureEngineSDK64.lib's VMEnd()/MutateEnd() verify at runtime that the
 * binary was Themida-processed; if not, they call TerminateProcess, which
 * cannot be caught by __try/__except.  This file overrides every __imp_*
 * IAT pointer so all SDK marker calls are routed to a harmless stub instead.
 *
 * The call sites (CALL [__imp_VMStart] / CALL [__imp_VMEnd] etc.) are
 * preserved in the binary exactly as Themida expects.  When Themida protection
 * IS applied later, it replaces those call sites with its own VM/mutation
 * code — these stubs are never executed in a protected build.
 *
 * To activate: remove SecureEngineSDK64.lib from the linker command and
 * comment out #pragma comment(lib, "SecureEngineSDK64.lib") in ThemidaSDK.h.
 */

/* Force the linker to keep every __imp_* data symbol below even when LTCG/
 * whole-program optimization decides they are "unreferenced" (the only refs
 * are through dllimport CALL [__imp_X] indirections in IL form, which the
 * IL eliminator does not see as a strong reference to the data symbol).
 *
 * Without these /INCLUDE directives, /GL+/LTCG silently strips the stubs and
 * link fails with LNK2001 on attach.obj/aura.obj/etc. Keep ONE pragma per
 * marker that is actually called somewhere in the codebase. */
#pragma comment(linker, "/INCLUDE:__imp_VMStart")
#pragma comment(linker, "/INCLUDE:__imp_VMEnd")
#pragma comment(linker, "/INCLUDE:__imp_MutateStart")
#pragma comment(linker, "/INCLUDE:__imp_MutateEnd")
#pragma comment(linker, "/INCLUDE:__imp_CodeReplaceStart")
#pragma comment(linker, "/INCLUDE:__imp_CodeReplaceEnd")
#pragma comment(linker, "/INCLUDE:__imp_EncodeStart")
#pragma comment(linker, "/INCLUDE:__imp_EncodeEnd")
#pragma comment(linker, "/INCLUDE:__imp_ClearStart")
#pragma comment(linker, "/INCLUDE:__imp_ClearEnd")
#pragma comment(linker, "/INCLUDE:__imp_StrEncryptStart")
#pragma comment(linker, "/INCLUDE:__imp_StrEncryptEnd")
#pragma comment(linker, "/INCLUDE:__imp_StrEncryptWStart")
#pragma comment(linker, "/INCLUDE:__imp_StrEncryptWEnd")
#pragma comment(linker, "/INCLUDE:__imp_RegisteredStart")
#pragma comment(linker, "/INCLUDE:__imp_RegisteredEnd")
#pragma comment(linker, "/INCLUDE:__imp_UnregisteredStart")
#pragma comment(linker, "/INCLUDE:__imp_UnregisteredEnd")
#pragma comment(linker, "/INCLUDE:__imp_RegisteredVMStart")
#pragma comment(linker, "/INCLUDE:__imp_RegisteredVMEnd")
#pragma comment(linker, "/INCLUDE:__imp_UnprotectedStart")
#pragma comment(linker, "/INCLUDE:__imp_UnprotectedEnd")
#pragma comment(linker, "/INCLUDE:__imp_SECheckProtection")
#pragma comment(linker, "/INCLUDE:__imp_SECheckCodeIntegrity")
#pragma comment(linker, "/INCLUDE:__imp_SECheckRegistration")
#pragma comment(linker, "/INCLUDE:__imp_SECheckVirtualPC")
#pragma comment(linker, "/INCLUDE:__imp_SECheckDebugger")

static void __stdcall _sdk_nop(void) { }

/* On MSVC x64, __declspec(dllimport) calls resolve through __imp_* pointers.
 * Defining them here as DATA symbols pointing to _sdk_nop makes every SDK
 * marker call a no-op without removing the call sites from the binary. */
void *__imp_VMStart             = (void *)_sdk_nop;
void *__imp_VMEnd               = (void *)_sdk_nop;
void *__imp_CodeReplaceStart    = (void *)_sdk_nop;
void *__imp_CodeReplaceEnd      = (void *)_sdk_nop;
void *__imp_RegisteredStart     = (void *)_sdk_nop;
void *__imp_RegisteredEnd       = (void *)_sdk_nop;
void *__imp_EncodeStart         = (void *)_sdk_nop;
void *__imp_EncodeEnd           = (void *)_sdk_nop;
void *__imp_ClearStart          = (void *)_sdk_nop;
void *__imp_ClearEnd            = (void *)_sdk_nop;
void *__imp_MutateStart         = (void *)_sdk_nop;
void *__imp_MutateEnd           = (void *)_sdk_nop;
void *__imp_StrEncryptStart     = (void *)_sdk_nop;
void *__imp_StrEncryptEnd       = (void *)_sdk_nop;
void *__imp_StrEncryptWStart    = (void *)_sdk_nop;
void *__imp_StrEncryptWEnd      = (void *)_sdk_nop;
void *__imp_UnregisteredStart   = (void *)_sdk_nop;
void *__imp_UnregisteredEnd     = (void *)_sdk_nop;
void *__imp_RegisteredVMStart   = (void *)_sdk_nop;
void *__imp_RegisteredVMEnd     = (void *)_sdk_nop;
void *__imp_UnprotectedStart    = (void *)_sdk_nop;
void *__imp_UnprotectedEnd      = (void *)_sdk_nop;
void *__imp_SECheckProtection   = (void *)_sdk_nop;
void *__imp_SECheckCodeIntegrity= (void *)_sdk_nop;
void *__imp_SECheckRegistration = (void *)_sdk_nop;
void *__imp_SECheckVirtualPC    = (void *)_sdk_nop;
void *__imp_SECheckDebugger     = (void *)_sdk_nop;
