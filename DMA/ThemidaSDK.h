/*
 * ThemidaSDK.h  --  DMA build Themida SDK gate.
 *
 * Mirrors the exact same guard used in Loader/ThemidaSDK.h:
 *
 *   Without SERAPH_THEMIDA_PROTECT  →  all markers are no-ops (dev / CI builds).
 *   With    SERAPH_THEMIDA_PROTECT  →  include the real Loader/ThemidaSDK.h which
 *                                      pulls in SecureEngineSDK64.lib and defines
 *                                      all real VM_START / MUTATE_START / etc.
 *
 * b_dma.bat adds /D "SERAPH_THEMIDA_PROTECT" for final (Themida-protected) builds.
 * The include path already has Loader/ so the redirect below resolves correctly.
 *
 * Key protection points in the DMA build:
 *   dma_entry.cpp  - VM_START around wWinMain body (auth, mutex, DLL extraction)
 *                  - MUTATE_START around IsRunningAsAdmin / single-instance logic
 *   dma_dll_loader.cpp - MUTATE_START around MachineHash (anti-static-analysis)
 */
#pragma once

#ifdef SERAPH_THEMIDA_PROTECT
/* The include path has DMA/ first, then Loader/.
 * Use a relative path to skip ourselves and reach Loader/ThemidaSDK.h. */
#include "../Loader/ThemidaSDK.h"
#else
/* ── No-op stubs (identical to Loader/ThemidaSDK.h's #ifndef SERAPH_THEMIDA_PROTECT block) */
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
#endif /* SERAPH_THEMIDA_PROTECT */
