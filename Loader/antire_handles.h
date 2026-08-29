/* antire_handles.h — AntiRE 2.0 handle-driven watcher (P6.2).
 *
 * Filosofia: detectar é pelo ATO de atacar nossa memória, não pela presença
 * de um nome no taskbar.  Cheat Engine aberto pra outro jogo = handle pra
 * outro PID = ignorado.  Aberto pra nós/D2 = trigger.
 *
 * Loop periódico (2s) chama NtQuerySystemInformation(SystemExtendedHandleInformation),
 * filtra entradas cujo OwnerPid != our_pid e Object handle aponta para
 * nosso_process ou d2_process com GrantedAccess perigoso (VM_READ|VM_WRITE|
 * QUERY_INFORMATION).  Owner é classificado: tier-1 nome → BAN; tier-2 →
 * grace + log; desconhecido → log.
 *
 * Em DEBUG só loga.  Em RELEASE (NDEBUG): KeyAuth_BanCurrentKey() +
 * Patch_RevertAll() (P6.3) + ExitProcess.
 */
#pragma once

#ifdef SERAPH_DMA_BUILD
#include "../DMA/antire_handles.h"
#else

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inicia thread de monitoramento.  ourPid: PID atual; d2Pid: 0 inicialmente,
 * setado depois via Set quando attach completar. */
void AntiRE_Handles_Start(DWORD ourPid);

/* Atualiza o PID do D2 quando descoberto pelo attach engine. */
void AntiRE_Handles_SetD2Pid(DWORD d2Pid);

/* Para o loop e libera recursos. */
void AntiRE_Handles_Stop(void);

/* P6.3: payload registra callback opcional para hot-revert (geralmente
 * `Patch_RestoreAll`).  Chamado ANTES de KeyAuth_Ban + ExitProcess para
 * apagar evidência no `.text` do D2.  NULL = no-op. */
typedef void (*AntiRE_HotRevertFn)(void);
void AntiRE_Handles_SetHotRevert(AntiRE_HotRevertFn fn);

#ifdef __cplusplus
}
#endif

#endif /* SERAPH_DMA_BUILD */
