/* self_hash.h — Stub.exe self-integrity check (P6.1).
 *
 * Compara o SHA256 do `.text` do binário em runtime com um valor
 * embedded no próprio binário pelo post-link script `tools/embed_hash.py`.
 * Mismatch indica que alguém adulterou o stub (debugger soft-patch,
 * unpacker dump-and-run, RE com modificações, AV repack).
 *
 * Em RELEASE: chama KeyAuth_BanCurrentKey() + ExitProcess.
 * Em DEBUG: só loga (não impede dev workflow).
 *
 * Layout do placeholder: 8 bytes magic "SERAPHHS" + 32 bytes 0xAA.
 * O script de post-link encontra essa assinatura e sobrescreve os 32 bytes
 * com o SHA256 do `.text`.
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verifica integridade do `.text`.  Retorna TRUE em sucesso (ou se o
 * placeholder ainda contém 0xAA — build dev sem post-link). */
#if !defined(NDEBUG) || defined(SERAPH_BUILD_PAYLOAD)
static inline BOOL SelfHash_Verify(void) {
    return TRUE;
}
#else
BOOL SelfHash_Verify(void);
#endif

#ifdef __cplusplus
}
#endif
