/*
 * ThemidaSDK.h  --  Themida protection gate for Seraph Loader.
 *
 * Two modes:
 *   Without SERAPH_THEMIDA_PROTECT  →  all markers are no-ops (dev / CI).
 *   With    SERAPH_THEMIDA_PROTECT  →  real function calls linked against
 *                                      SecureEngineSDK64.lib, recognized by
 *                                      Themida at protect-time.
 *
 * b_release.bat adds /D "SERAPH_THEMIDA_PROTECT".
 */
#pragma once

#ifndef SERAPH_THEMIDA_PROTECT
/* ── No-op stubs (dev / debug builds) ─────────────────────────────────── */
#define VM_START                          ((void)0);
#define VM_END                            ((void)0);
#define VM_START_WITHLEVEL(x)             ((void)0);
#define CODEREPLACE_START                 ((void)0);
#define CODEREPLACE_END                   ((void)0);
#define ENCODE_START                      ((void)0);
#define ENCODE_END                        ((void)0);
#define CLEAR_START                       ((void)0);
#define CLEAR_END                         ((void)0);
#define MUTATE_START                      ((void)0);
#define MUTATE_END                        ((void)0);
#define STR_ENCRYPT_START                 ((void)0);
#define STR_ENCRYPT_END                   ((void)0);
#define STR_ENCRYPTW_START                ((void)0);
#define STR_ENCRYPTW_END                  ((void)0);
#define UNREGISTERED_START                ((void)0);
#define UNREGISTERED_END                  ((void)0);
#define UNPROTECTED_START                 ((void)0);
#define UNPROTECTED_END                   ((void)0);
#define REGISTERED_START                  ((void)0);
#define REGISTERED_END                    ((void)0);
#define REGISTEREDVM_START                ((void)0);
#define REGISTEREDVM_END                  ((void)0);
#define CHECK_PROTECTION(var, val)        ((void)0);
#define CHECK_CODE_INTEGRITY(var, val)    ((void)0);
#define CHECK_REGISTRATION(var, val)      ((void)0);
#define CHECK_VIRTUAL_PC(var, val)        ((void)0);
#define CHECK_DEBUGGER(var, val)          ((void)0);

#else /* SERAPH_THEMIDA_PROTECT — real Themida markers via __imp_* IAT */

/* ── Declare the SDK symbols that Themida looks for in the IAT ──────────
 * __declspec(dllimport) makes the compiler emit CALL [__imp_VMStart] etc.
 * — the exact call-site pattern that Themida recognizes at protect-time.
 *
 * The __imp_* DATA symbols are provided by themida_stubs.c (no-op stubs).
 * SecureEngineSDK64.lib is NOT needed — the stubs satisfy the linker and
 * Themida replaces the CALL sites in the final protected binary. */
#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllimport) void __stdcall VMStart(void);
__declspec(dllimport) void __stdcall VMEnd(void);
__declspec(dllimport) void __stdcall MutateStart(void);
__declspec(dllimport) void __stdcall MutateEnd(void);
__declspec(dllimport) void __stdcall EncodeStart(void);
__declspec(dllimport) void __stdcall EncodeEnd(void);
#ifdef __cplusplus
}
#endif

#define VM_START                          VMStart();
#define VM_END                            VMEnd();
#ifdef SERAPH_DISABLE_MUTATE
#define MUTATE_START                      ((void)0);
#define MUTATE_END                        ((void)0);
#else
#define MUTATE_START                      MutateStart();
#define MUTATE_END                        MutateEnd();
#endif
#define ENCODE_START                      EncodeStart();
#define ENCODE_END                        EncodeEnd();

/* All other macros are unused in the Loader codebase */
#define VM_START_WITHLEVEL(x)             ((void)0);
#define CODEREPLACE_START                 ((void)0);
#define CODEREPLACE_END                   ((void)0);
#define CLEAR_START                       ((void)0);
#define CLEAR_END                         ((void)0);
#define STR_ENCRYPT_START                 ((void)0);
#define STR_ENCRYPT_END                   ((void)0);
#define STR_ENCRYPTW_START                ((void)0);
#define STR_ENCRYPTW_END                  ((void)0);
#define UNREGISTERED_START                ((void)0);
#define UNREGISTERED_END                  ((void)0);
#define UNPROTECTED_START                 ((void)0);
#define UNPROTECTED_END                   ((void)0);
#define REGISTERED_START                  ((void)0);
#define REGISTERED_END                    ((void)0);
#define REGISTEREDVM_START                ((void)0);
#define REGISTEREDVM_END                  ((void)0);
#define CHECK_PROTECTION(var, val)        ((void)0);
#define CHECK_CODE_INTEGRITY(var, val)    ((void)0);
#define CHECK_REGISTRATION(var, val)      ((void)0);
#define CHECK_VIRTUAL_PC(var, val)        ((void)0);
#define CHECK_DEBUGGER(var, val)          ((void)0);

#endif /* SERAPH_THEMIDA_PROTECT */