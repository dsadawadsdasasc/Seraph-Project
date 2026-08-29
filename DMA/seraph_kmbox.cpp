#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

#include "seraph_kmbox.h"
#include "kmbox/kmboxNet.h"
#include "seraph_secure_val.h"
#include "seraph_handle_bucket.h"
#include "XorStr.h"

#ifdef SERAPH_DMA_BUILD

static SeraphKmboxSettings g_settings = {
    SERAPH_KMBOX_OFF,
    1,  /* hw_aim */
    0,  /* auto_connect */
    "",
    "",
    "",
    "",
    ""
};

/* Criptografa flags do KMBox dinamicamente usando SecureVal96 */
static SecureVal96 g_settings_device_type;
static SecureVal96 g_settings_hw_aim;
static SecureVal96 g_settings_auto_connect;
static SecureVal96 g_netConnected_sec;
static INT32 g_comPortObf = 0;

static float g_accX = 0.f;
static float g_accY = 0.f;
static DWORD g_lastSendMs = 0;

SeraphKmboxSettings *SeraphKmbox_GetSettings(void)
{
    /* Inicializa chaves e strings no primeiro acesso se necessário */
    static BOOL inited = FALSE;
    if (!inited) {
        strcpy_s(g_settings.ip, sizeof(g_settings.ip), DXOR_A(ENC_kmbox_default_ip));
        strcpy_s(g_settings.port, sizeof(g_settings.port), DXOR_A(ENC_kmbox_default_port));
        strcpy_s(g_settings.com_port, sizeof(g_settings.com_port), DXOR_A(ENC_kmbox_default_com));
        strcpy_s(g_settings.baud_str, sizeof(g_settings.baud_str), DXOR_A(ENC_kmbox_default_baud));

        SecureWrite(&g_settings_device_type, SERAPH_KMBOX_OFF);
        SecureWrite(&g_settings_hw_aim, 1);
        SecureWrite(&g_settings_auto_connect, 0);
        SecureWrite(&g_netConnected_sec, FALSE);
        inited = TRUE;
    }

    static SeraphKmboxSettings s_dec_settings;
    s_dec_settings = g_settings;
    
    s_dec_settings.device_type = (int)SecureRead(&g_settings_device_type);
    s_dec_settings.hw_aim = (int)SecureRead(&g_settings_hw_aim);
    s_dec_settings.auto_connect = (int)SecureRead(&g_settings_auto_connect);
    return &s_dec_settings;
}

static void NetDisconnect(void)
{
    if (SecureRead(&g_netConnected_sec) && sockClientfd != 0 && sockClientfd != INVALID_SOCKET) {
        closesocket(sockClientfd);
        sockClientfd = 0;
        WSACleanup();
    }
    SecureWrite(&g_netConnected_sec, FALSE);
}

static BOOL NetConnect(void)
{
    if (g_settings.ip[0] == '\0' || g_settings.port[0] == '\0' || g_settings.uuid[0] == '\0')
        return FALSE;
    /* Stale flag with dead socket — force reconnect. */
    if (SecureRead(&g_netConnected_sec) && (sockClientfd == 0 || sockClientfd == INVALID_SOCKET))
        SecureWrite(&g_netConnected_sec, FALSE);
    if (SecureRead(&g_netConnected_sec))
        return TRUE;

    if (kmNet_init(g_settings.ip, g_settings.port, g_settings.uuid) != 0) {
        SecureWrite(&g_netConnected_sec, FALSE);
        return FALSE;
    }

    extern sockaddr_in addrSrv;
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons((u_short)atoi(g_settings.port));
    addrSrv.sin_addr.S_un.S_addr = inet_addr(g_settings.ip);

    SecureWrite(&g_netConnected_sec, TRUE);
    return TRUE;
}

static void BplusClose(void)
{
    HANDLE h = (HANDLE)SeraphHB_Lookup(g_comPortObf);
    if (h && h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        SeraphHB_Remove(g_comPortObf);
        g_comPortObf = 0;
    }
}

static BOOL IsDigitsOnly(const char *s)
{
    if (!s || !*s) return FALSE;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return FALSE;
    }
    return TRUE;
}

static int ParseComNumber(const char *text)
{
    if (!text || !*text) return -1;
    std::string s(text);
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    if (s.size() >= 4 &&
        (s[0] == 'C' || s[0] == 'c') &&
        (s[1] == 'O' || s[1] == 'o') &&
        (s[2] == 'M' || s[2] == 'm'))
    {
        std::string tail = s.substr(3);
        if (!IsDigitsOnly(tail.c_str())) return -1;
        return atoi(tail.c_str());
    }
    if (!IsDigitsOnly(s.c_str())) return -1;
    return atoi(s.c_str());
}

static BOOL BplusWriteLine(const char *line)
{
    HANDLE h = (HANDLE)SeraphHB_Lookup(g_comPortObf);
    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD w = 0;
    size_t len = strlen(line);
    if (!WriteFile(h, line, (DWORD)len, &w, NULL) || w != len) return FALSE;
    const char crlf[2] = {'\r', '\n'};
    return WriteFile(h, crlf, 2, &w, NULL) && w == 2;
}

static BOOL BplusConnect(void)
{
    BplusClose();
    int com = ParseComNumber(g_settings.com_port);
    DWORD baud = (DWORD)strtoul(g_settings.baud_str, NULL, 10);
    if (com <= 0 || baud < 1200 || baud > 10000000UL) return FALSE;

    char path[32];
    snprintf(path, sizeof(path), DXOR_A(ENC_kmbox_com_path_fmt), com);
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    DCB dcb = {};
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) { CloseHandle(h); return FALSE; }
    dcb.BaudRate = baud;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    if (!SetCommState(h, &dcb)) { CloseHandle(h); return FALSE; }

    COMMTIMEOUTS t = {};
    t.ReadIntervalTimeout = 0xFFFFFFFF;
    t.ReadTotalTimeoutConstant = 50;
    t.WriteTotalTimeoutConstant = 50;
    SetCommTimeouts(h, &t);
    PurgeComm(h, PURGE_TXCLEAR | PURGE_RXCLEAR);

    g_comPortObf = SeraphHB_Insert(h);
    return TRUE;
}

static void BplusMove(int dx, int dy)
{
    HANDLE h = (HANDLE)SeraphHB_Lookup(g_comPortObf);
    if (!h || h == INVALID_HANDLE_VALUE) return;
    char buf[64];
    snprintf(buf, sizeof(buf), DXOR_A(ENC_kmbox_cmd_move), dx, dy);
    if (!BplusWriteLine(buf)) {
        snprintf(buf, sizeof(buf), DXOR_A(ENC_kmbox_cmd_mouse_move), dx, dy);
        BplusWriteLine(buf);
    }
}

void SeraphKmbox_Disconnect(void)
{
    NetDisconnect();
    BplusClose();
    g_accX = 0.f;
    g_accY = 0.f;
    g_lastSendMs = 0;
}

void SeraphKmbox_Connect(void)
{
    SeraphKmbox_Disconnect();
    int device_type = (int)SecureRead(&g_settings_device_type);
    if (device_type == SERAPH_KMBOX_NET)
        NetConnect();
    else if (device_type == SERAPH_KMBOX_BPLUS)
        BplusConnect();
}

static BOOL IsComPortValid(void) {
    HANDLE h = (HANDLE)SeraphHB_Lookup(g_comPortObf);
    return (h && h != INVALID_HANDLE_VALUE);
}

/* Returns TRUE only when hw_aim is on AND a connection is active.
 * Used by MoveAccum / aimbot to decide whether to send mouse moves. */
BOOL SeraphKmbox_IsReady(void)
{
    int device_type = (int)SecureRead(&g_settings_device_type);
    int hw_aim = (int)SecureRead(&g_settings_hw_aim);
    if (!hw_aim || device_type == SERAPH_KMBOX_OFF)
        return FALSE;
    if (device_type == SERAPH_KMBOX_NET)
        return (BOOL)SecureRead(&g_netConnected_sec);
    if (device_type == SERAPH_KMBOX_BPLUS)
        return IsComPortValid();
    return FALSE;
}

/* Returns TRUE whenever a physical connection exists, regardless of hw_aim.
 * Used by the UI to show accurate connection status in the KmBox modal. */
BOOL SeraphKmbox_IsConnected(void)
{
    int device_type = (int)SecureRead(&g_settings_device_type);
    if (device_type == SERAPH_KMBOX_NET)   return (BOOL)SecureRead(&g_netConnected_sec);
    if (device_type == SERAPH_KMBOX_BPLUS) return IsComPortValid();
    return FALSE;
}

void SeraphKmbox_AutoConnect(void)
{
    int device_type = (int)SecureRead(&g_settings_device_type);
    int auto_connect = (int)SecureRead(&g_settings_auto_connect);
    if (!auto_connect || device_type == SERAPH_KMBOX_OFF)
        return;
    if (SeraphKmbox_IsReady())
        return;

    static DWORD lastAttempt = 0;
    DWORD now = GetTickCount();
    if (now - lastAttempt < 5000)
        return;
    lastAttempt = now;
    SeraphKmbox_Connect();
}

static void SendMove(int dx, int dy)
{
    if (dx == 0 && dy == 0) return;
    int device_type = (int)SecureRead(&g_settings_device_type);
    if (device_type == SERAPH_KMBOX_NET && SecureRead(&g_netConnected_sec)) {
        if (kmNet_mouse_move((short)dx, (short)dy) != 0)
            NetDisconnect();
    } else if (device_type == SERAPH_KMBOX_BPLUS && IsComPortValid()) {
        BplusMove(dx, dy);
    }
}

void SeraphKmbox_MoveAccum(int dx, int dy)
{
    if (!SeraphKmbox_IsReady()) return;

    g_accX += (float)dx;
    g_accY += (float)dy;

    DWORD now = GetTickCount();
    DWORD dt = (g_lastSendMs == 0) ? 1000 : (now - g_lastSendMs);

    BOOL isFlick = (dx > 10 || dx < -10 || dy > 10 || dy < -10);
    if (dt < 7 && !isFlick)
        return;

    int ix = (int)(g_accX + (g_accX >= 0.f ? 0.5f : -0.5f));
    int iy = (int)(g_accY + (g_accY >= 0.f ? 0.5f : -0.5f));
    if (ix == 0 && iy == 0)
        return;

    SendMove(ix, iy);
    g_accX -= (float)ix;
    g_accY -= (float)iy;
    g_lastSendMs = now;
}

void SeraphKmbox_LeftClick(int isdown)
{
    if (!SeraphKmbox_IsReady()) return;
    int device_type = (int)SecureRead(&g_settings_device_type);
    if (device_type == SERAPH_KMBOX_NET && SecureRead(&g_netConnected_sec)) {
        if (kmNet_mouse_left(isdown) != 0)
            NetDisconnect();
    } else if (device_type == SERAPH_KMBOX_BPLUS && IsComPortValid()) {
        HANDLE h = (HANDLE)SeraphHB_Lookup(g_comPortObf);
        if (h && h != INVALID_HANDLE_VALUE) {
            char buf[64];
            snprintf(buf, sizeof(buf), DXOR_A(ENC_kmbox_cmd_left), isdown);
            BplusWriteLine(buf);
        }
    }
}

#endif /* SERAPH_DMA_BUILD */
