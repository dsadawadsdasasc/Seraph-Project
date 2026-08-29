/* stub_stomp.h — Module stomping engine (P4-alt.3).
 *
 * Reescreve a imagem inteira de uma DLL "vítima" já carregada com a
 * imagem (decifrada) do svc.dll payload.  Aplica relocs + resolve imports
 * manualmente.  Devolve o ponteiro para PayloadMain dentro da vítima.
 *
 * Política atual: usa NtProtectVirtualMemory + memcpy in-self para o
 * stomp.  ETW Threat Intel pode logar isso; aceitamos pois (a) Stub.exe
 * roda antes do D2 injetar BEClient e (b) a alternativa via BYOVD físico
 * exige CtiIo64.sys no stub também — TODO futuro (Fase 8).
 *
 * Após PayloadMain retornar, chamar StubStomp_Revert para restaurar a
 * vítima ao estado original (snapshot vivido em StubVictim).
 */
#pragma once
#include <windows.h>
#include "stub_pe_parser.h"
#include "stub_victim.h"
#include "payload_ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Faz o stomp completo + retorna PayloadMain pronto para chamar.
 *   pe         = payload já parsado
 *   victim     = DLL vítima já escolhida com SizeOfImage suficiente
 *   outEntry   = recebe ponteiro para PayloadMain dentro da vítima
 * Retorna 0 em sucesso; negativo em erro:
 *   -1 args / fit
 *   -2 NtProtectVirtualMemory falhou
 *   -3 falha em aplicar relocs
 *   -4 falha em resolver imports
 *   -5 export PayloadMain não encontrado
 */
typedef int (__cdecl *PFN_PayloadMain)(const PayloadCtx*);

int  StubStomp_Apply(const StubPE* pe, StubVictim* victim,
                     PFN_PayloadMain* outEntry);

/* Reverte o stomp restaurando bytes originais via snapshot. */
int  StubStomp_Revert(StubVictim* victim);

#ifdef __cplusplus
}
#endif
