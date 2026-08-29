#define WIN32_LEAN_AND_MEAN
#include "kmboxNet.h"
#include "HidTable.h"
#include <time.h>
#define monitor_ok    2
#define monitor_exit  0
SOCKET sockClientfd  = 0;				//¼üÊóÍøÂçÍ¨ĞÅ¾ä±ú
SOCKET sockMonitorfd = 0;				//¼àÌıÍøÂçÍ¨ĞÅ¾ä±ú
client_tx tx;							//·¢ËÍµÄÄÚÈİ
client_tx rx;							//½ÓÊÕµÄÄÚÈİ
SOCKADDR_IN addrSrv;
soft_mouse_t    softmouse;				//Èí¼şÊó±êÊı¾İ
soft_keyboard_t softkeyboard;			//Èí¼ş¼üÅÌÊı¾İ
static int monitor_run = 0;				//ÎïÀí¼üÊó¼à¿ØÊÇ·ñÔËĞĞ
static int mask_keyboard_mouse_flag = 0;//¼üÊóÆÁ±Î×´Ì¬
static short monitor_port = 0;


#pragma pack(1)
typedef struct {
	unsigned char report_id;
	unsigned char buttons;		// 8 buttons available
	short x;					// -32767 to 32767
	short y;					// -32767 to 32767
	short wheel;				// -32767 to 32767
}standard_mouse_report_t;

typedef struct {
	unsigned char report_id;
	unsigned char buttons;      // 8 buttons¿ØÖÆ¼ü
	unsigned char data[10];     //³£¹æ°´¼ü
}standard_keyboard_report_t;
#pragma pack()

standard_mouse_report_t		hw_mouse;   //Ó²¼şÊó±êÏûÏ¢
standard_keyboard_report_t	hw_keyboard;//Ó²¼ş¼üÅÌÏûÏ¢

//Éú³ÉÒ»¸öAµ½BÖ®¼äµÄËæ»úÊı
int myrand(int a, int b)
{
	int min = a < b ? a : b;
	int max = a > b ? a : b;
	return ((rand() % (max - min)) + min);
}

unsigned int StrToHex(char* pbSrc, int nLen)
{
	char h1, h2;
	unsigned char s1, s2;
	int i;
	unsigned int pbDest[16] = { 0 };
	for (i = 0; i < nLen; i++) {
		h1 = pbSrc[2 * i];
		h2 = pbSrc[2 * i + 1];
		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
			s1 -= 7;
		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;
		pbDest[i] = s1 * 16 + s2;
	}
	return pbDest[0] << 24 | pbDest[1] << 16 | pbDest[2] << 8 | pbDest[3];
}

int NetRxReturnHandle(client_tx* rx, client_tx* tx)		 //½ÓÊÕµÄÄÚÈİ
{
	if (rx->head.cmd != tx->head.cmd)
		return  err_net_cmd;//ÃüÁîÂë´íÎó
	if (rx->head.indexpts != tx->head.indexpts)
		return  err_net_pts;//Ê±¼ä´Á´íÎó
	return 0;				//Ã»ÓĞ´íÎó·µ»Ø0
	//return  rx->head.rand;//ÕæÕıµÄ·µ»ØÖµ


}


/*
Á¬½ÓkmboxNetºĞ×ÓÊäÈë²ÎÊı·Ö±ğÊÇºĞ×Ó
ip  £ººĞ×ÓµÄIPµØÖ· £¨ÏÔÊ¾ÆÁÉÏ»áÓĞÏÔÊ¾,ÀıÈç£º192.168.2.88£©
port: Í¨ĞÅ¶Ë¿ÚºÅ   £¨ÏÔÊ¾ÆÁÉÏ»áÓĞÏÔÊ¾£¬ÀıÈç£º6234£©
mac : ºĞ×ÓµÄmacµØÖ·£¨ÏÔÊ¾ÆÁÄ»ÉÏÓĞÏÔÊ¾£¬ÀıÈç£º12345£©
·µ»ØÖµ:0Õı³££¬·ÇÁãÖµÇë¿´´íÎó´úÂë
*/
int kmNet_init(char* ip, char* port, char* mac)
{
    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) return err_creat_socket;

    sockClientfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockClientfd == INVALID_SOCKET) {
        WSACleanup();
        return err_creat_socket;
    }

    // --- single-attempt timeout (ms) ---
    DWORD timeout_ms = 500; // pick what feels right (500ms–1000ms)
    setsockopt(sockClientfd, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(sockClientfd, SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(static_cast<u_short>(atoi(port)));
    srv.sin_addr.S_un.S_addr = inet_addr(ip);

    // prepare tx packet
    srand((unsigned)time(NULL));
    tx.head.mac = StrToHex(mac, 4);
    tx.head.rand = rand();
    tx.head.indexpts = 0;
    tx.head.cmd = cmd_connect;

    // send once
    int sret = sendto(sockClientfd, (const char*)&tx, sizeof(cmd_head_t), 0,
        (struct sockaddr*)&srv, sizeof(srv));
    if (sret == SOCKET_ERROR) {
        closesocket(sockClientfd); WSACleanup();
        return err_creat_socket;
    }

    // wait once
    int clen = sizeof(srv);
    int rret = recvfrom(sockClientfd, (char*)&rx, 1024, 0,
        (struct sockaddr*)&srv, &clen);
    if (rret == SOCKET_ERROR) {
        int werr = WSAGetLastError();
        closesocket(sockClientfd); WSACleanup();
        return (werr == WSAETIMEDOUT) ? err_net_rx_timeout : err_net_version;
    }

    return NetRxReturnHandle(&rx, &tx);
}

/*
Êó±êÒÆ¶¯x,y¸öµ¥Î»¡£Ò»´ÎĞÔÒÆ¶¯¡£ÎŞ¹ì¼£Ä£Äâ£¬ËÙ¶È×î¿ì.
×Ô¼ºĞ´¹ì¼£ÒÆ¶¯Ê±Ê¹ÓÃ´Ëº¯Êı¡£
·µ»ØÖµ£º0Õı³£Ö´ĞĞ£¬ÆäËûÖµÒì³£¡£
*/
#include <cstdio>
#include <cstring>
#include <WS2tcpip.h>

constexpr int err_net_send_fail = -9001;
constexpr int err_net_rx_fail = -9002;

int kmNet_mouse_move(short x, short y)
{
    if (sockClientfd == INVALID_SOCKET) {
        std::fprintf(stderr, "[kmNet] ERROR: invalid socket (INVALID_SOCKET)\n");
        return err_creat_socket;
    }

    // Sanity: check addrSrv family/port (debug)
    const sockaddr_in* dst = reinterpret_cast<const sockaddr_in*>(&addrSrv);
    if (dst->sin_family != AF_INET || dst->sin_port == 0) {
        std::fprintf(stderr, "[kmNet] ERROR: addrSrv not initialized: fam=%d port=%u\n",
            dst->sin_family, ntohs(dst->sin_port));
        return err_creat_socket;
    }

    tx.head.indexpts++;
    tx.head.cmd = cmd_mouse_move;
    tx.head.rand = rand();
    softmouse.x = x;
    softmouse.y = y;

    memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
    int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);

    int sent = sendto(sockClientfd,
        reinterpret_cast<const char*>(&tx),
        length,
        0,
        reinterpret_cast<const sockaddr*>(&addrSrv),
        sizeof(addrSrv));
    if (sent != length) {
        int wsaErr = WSAGetLastError();
        std::fprintf(stderr,
            "[kmNet] ERROR: sendto failed (sent=%d expected=%d WSA=%d)\n",
            sent, length, wsaErr);
        return err_net_send_fail;
    }

    softmouse.x = 0;
    softmouse.y = 0;

    SOCKADDR_IN sclient{};
    int clen = sizeof(sclient);
    int recvd = recvfrom(sockClientfd,
        reinterpret_cast<char*>(&rx),
        sizeof(rx),
        0,
        reinterpret_cast<sockaddr*>(&sclient),
        &clen);
    if (recvd < 0) {
        int wsaErr = WSAGetLastError();
        if (wsaErr == WSAETIMEDOUT) {
            std::fprintf(stderr, "[kmNet] ERROR: recvfrom timeout (WSA=%d)\n", wsaErr);
            return err_net_rx_timeout;
        }
        std::fprintf(stderr, "[kmNet] ERROR: recvfrom failed (rc=%d WSA=%d)\n", recvd, wsaErr);
        return err_net_rx_fail;
    }

    return NetRxReturnHandle(&rx, &tx);
}


/*
Êó±ê×ó¼ü¿ØÖÆ
isdown :0ËÉ¿ª £¬1°´ÏÂ
·µ»ØÖµ£º0Õı³£Ö´ĞĞ£¬ÆäËûÖµÒì³£¡£
*/
int kmNet_mouse_left(int isdown)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_left;	//Ö¸Áî
	tx.head.rand = rand();			//Ëæ»ú»ìÏıÖµ
	softmouse.button = (isdown ? (softmouse.button | 0x01) : (softmouse.button & (~0x01)));
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

/*
Êó±êÖĞ¼ü¿ØÖÆ
isdown :0ËÉ¿ª £¬1°´ÏÂ
·µ»ØÖµ£º0Õı³£Ö´ĞĞ£¬ÆäËûÖµÒì³£¡£
*/
int kmNet_mouse_middle(int isdown)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_middle;	//Ö¸Áî
	tx.head.rand = rand();			//Ëæ»ú»ìÏıÖµ
	softmouse.button = (isdown ? (softmouse.button | 0x04) : (softmouse.button & (~0x04)));
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

/*
Êó±êÓÒ¼ü¿ØÖÆ
isdown :0ËÉ¿ª £¬1°´ÏÂ
·µ»ØÖµ£º0Õı³£Ö´ĞĞ£¬ÆäËûÖµÒì³£¡£
*/
int kmNet_mouse_right(int isdown)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_right;	//Ö¸Áî
	tx.head.rand = rand();			//Ëæ»ú»ìÏıÖµ
	softmouse.button = (isdown ? (softmouse.button | 0x02) : (softmouse.button & (~0x02)));
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

//Êó±ê¹öÂÖ¿ØÖÆ
int kmNet_mouse_wheel(int wheel)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_wheel;	//Ö¸Áî
	tx.head.rand = rand();			//Ëæ»ú»ìÏıÖµ
	softmouse.wheel = wheel;
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	softmouse.wheel = 0;
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


/*
Êó±êÈ«±¨¸æ¿ØÖÆº¯Êı
*/
int kmNet_mouse_all(int button, int x, int y, int wheel)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_wheel;	//Ö¸Áî
	tx.head.rand = rand();			//Ëæ»ú»ìÏıÖµ
	softmouse.button = button;
	softmouse.x = x;
	softmouse.y = y;
	softmouse.wheel = wheel;
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	softmouse.x = 0;
	softmouse.y = 0;
	softmouse.wheel = 0;
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

/*
Êó±êÒÆ¶¯x,y¸öµ¥Î»¡£Ä£ÄâÈËÎªÒÆ¶¯x,y¸öµ¥Î»¡£²»»á³öÏÖ¼üÊóÒì³£µÄ¼ì²â.
Ã»ÓĞĞ´ÒÆ¶¯ÇúÏßµÄÍÆ¼öÓÃ´Ëº¯Êı¡£´Ëº¯Êı²»»á³öÏÖÌøÔ¾ÏÖÏó£¬°´ÕÕ×îĞ¡²½½ø±Æ½ü
Ä¿±êµã¡£ºÄÊ±±ÈkmNet_mouse_move¸ß¡£
msÊÇÉèÖÃÒÆ¶¯ĞèÒª¶àÉÙºÁÃë.×¢Òâms¸øµÄÖµ²»ÒªÌ«Ğ¡£¬Ì«Ğ¡Ò»Ñù»á³öÏÖ¼üÊóÊı¾İÒì³£¡£
¾¡Á¿ÏñÈË²Ù×÷¡£Êµ¼ÊÓÃÊ±»á±ÈmsĞ¡¡£
*/
int kmNet_mouse_move_auto(int x, int y, int ms)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				 //Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mouse_automove;//Ö¸Áî
	tx.head.rand = ms;			     //Ëæ»ú»ìÏıÖµ
	softmouse.x = x;
	softmouse.y = y;
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	softmouse.x = 0;				//ÇåÁã
	softmouse.y = 0;				//ÇåÁã
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}



/*
¶ş½×±´Èû¶ûÇúÏß¿ØÖÆ
x,y 	:Ä¿±êµã×ø±ê
ms		:ÄâºÏ´Ë¹ı³ÌÓÃÊ±£¨µ¥Î»ms£©
x1,y1	:¿ØÖÆµãp1µã×ø±ê
x2,y2	:¿ØÖÆµãp2µã×ø±ê
*/
int kmNet_mouse_move_beizer(int x, int y, int ms, int x1, int y1, int x2, int y2)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;			 //Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_bazerMove; //Ö¸Áî
	tx.head.rand = ms;			 //Ëæ»ú»ìÏıÖµ
	softmouse.x = x;
	softmouse.y = y;
	softmouse.point[0] = x1;
	softmouse.point[1] = y1;
	softmouse.point[2] = x2;
	softmouse.point[3] = y2;
	memcpy(&tx.cmd_mouse, &softmouse, sizeof(soft_mouse_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_mouse_t);
	softmouse.x = 0;
	softmouse.y = 0;
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}



int kmNet_keydown(int vk_key)
{
	int i;
	if (vk_key >= KEY_LEFTCONTROL && vk_key <= KEY_RIGHT_GUI)//¿ØÖÆ¼ü
	{
		switch (vk_key)
		{
		case KEY_LEFTCONTROL: softkeyboard.ctrl |= BIT0; break;
		case KEY_LEFTSHIFT:   softkeyboard.ctrl |= BIT1; break;
		case KEY_LEFTALT:     softkeyboard.ctrl |= BIT2; break;
		case KEY_LEFT_GUI:    softkeyboard.ctrl |= BIT3; break;
		case KEY_RIGHTCONTROL:softkeyboard.ctrl |= BIT4; break;
		case KEY_RIGHTSHIFT:  softkeyboard.ctrl |= BIT5; break;
		case KEY_RIGHTALT:    softkeyboard.ctrl |= BIT6; break;
		case KEY_RIGHT_GUI:   softkeyboard.ctrl |= BIT7; break;
		}
	}
	else
	{//³£¹æ¼ü  
		for (i = 0; i < 10; i++)//Ê×ÏÈ¼ì²é¶ÓÁĞÖĞÊÇ·ñ´æÔÚvk_key
		{
			if (softkeyboard.button[i] == vk_key)
				goto KM_down_send;// ¶ÓÁĞÀïÃæÒÑ¾­ÓĞvk_key Ö±½Ó·¢ËÍ¾ÍĞĞ
		}
		//¶ÓÁĞÀïÃæÃ»ÓĞvk_key 
		for (i = 0; i < 10; i++)//±éÀúËùÓĞµÄÊı¾İ£¬½«vk_keyÌí¼Óµ½¶ÓÁĞÀï
		{
			if (softkeyboard.button[i] == 0)
			{// ¶ÓÁĞÀïÃæÒÑ¾­ÓĞvk_key Ö±½Ó·¢ËÍ¾ÍĞĞ
				softkeyboard.button[i] = vk_key;
				goto KM_down_send;
			}
		}
		//¶ÓÁĞÒÑ¾­ÂúÁË ÄÇÃ´¾ÍÌŞ³ı×î¿ªÊ¼µÄÄÇ¸ö
		memcpy(&softkeyboard.button[0], &softkeyboard.button[1], 10);
		softkeyboard.button[9] = vk_key;
	}
KM_down_send:
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_keyboard_all;	//Ö¸Áî
	tx.head.rand = rand();			// Ëæ»ú»ìÏıÖµ
	memcpy(&tx.cmd_keyboard, &softkeyboard, sizeof(soft_keyboard_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_keyboard_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}




int kmNet_keyup(int vk_key)
{
	int i;
	if (vk_key >= KEY_LEFTCONTROL && vk_key <= KEY_RIGHT_GUI)//¿ØÖÆ¼ü
	{
		switch (vk_key)
		{
		case KEY_LEFTCONTROL: softkeyboard.ctrl &= ~BIT0; break;
		case KEY_LEFTSHIFT:   softkeyboard.ctrl &= ~BIT1; break;
		case KEY_LEFTALT:     softkeyboard.ctrl &= ~BIT2; break;
		case KEY_LEFT_GUI:    softkeyboard.ctrl &= ~BIT3; break;
		case KEY_RIGHTCONTROL:softkeyboard.ctrl &= ~BIT4; break;
		case KEY_RIGHTSHIFT:  softkeyboard.ctrl &= ~BIT5; break;
		case KEY_RIGHTALT:    softkeyboard.ctrl &= ~BIT6; break;
		case KEY_RIGHT_GUI:   softkeyboard.ctrl &= ~BIT7; break;
		}
	}
	else
	{//³£¹æ¼ü  
		for (i = 0; i < 10; i++)//Ê×ÏÈ¼ì²é¶ÓÁĞÖĞÊÇ·ñ´æÔÚvk_key
		{
			if (softkeyboard.button[i] == vk_key)// ¶ÓÁĞÀïÃæÒÑ¾­ÓĞvk_key 
			{
				memcpy(&softkeyboard.button[i], &softkeyboard.button[i + 1], 10 - i);
				softkeyboard.button[9] = 0;
				goto KM_up_send;
			}
		}
	}
KM_up_send:
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_keyboard_all;	//Ö¸Áî
	tx.head.rand = rand();			// Ëæ»ú»ìÏıÖµ
	memcpy(&tx.cmd_keyboard, &softkeyboard, sizeof(soft_keyboard_t));
	int length = sizeof(cmd_head_t) + sizeof(soft_keyboard_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÖØÆôºĞ×Ó
int kmNet_reboot(void)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_reboot;		//Ö¸Áî
	tx.head.rand = rand();			// Ëæ»ú»ìÏıÖµ
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	WSACleanup();
	sockClientfd = -1;
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);

}



//¼àÌıÎïÀí¼üÊó
//static HANDLE handle_listen = NULL;
DWORD WINAPI ThreadListenProcess(LPVOID lpParameter)
{
	WSADATA wsaData; int ret;
	WSAStartup(MAKEWORD(1, 1), &wsaData);			//´´½¨Ì×½Ó×Ö£¬SOCK_DGRAMÖ¸Ã÷Ê¹ÓÃ UDP Ğ­Òé
	sockMonitorfd = socket(AF_INET, SOCK_DGRAM, 0);	//°ó¶¨Ì×½Ó×Ö
	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));			//Ã¿¸ö×Ö½Ú¶¼ÓÃ0Ìî³ä
	servAddr.sin_family		 = PF_INET;				//Ê¹ÓÃIPv4µØÖ·
	servAddr.sin_addr.s_addr = INADDR_ANY;	        //×Ô¶¯»ñÈ¡IPµØÖ·
	servAddr.sin_port = htons(monitor_port);		//¼àÌı¶Ë¿Ú
	ret=bind(sockMonitorfd, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));
	SOCKADDR cliAddr;  //¿Í»§¶ËµØÖ·ĞÅÏ¢
	int nSize = sizeof(SOCKADDR);
	char buff[1024];  //»º³åÇø
	monitor_run = monitor_ok;
	while (1) {
		int ret=recvfrom(sockMonitorfd, buff, 1024, 0, &cliAddr, &nSize);	//×èÈû¶ÁÊı¾İ
		if (ret > 0)
		{
			memcpy(&hw_mouse, buff, sizeof(hw_mouse));							//ÎïÀíÊó±ê×´Ì¬
			memcpy(&hw_keyboard, &buff[sizeof(hw_mouse)], sizeof(hw_keyboard));	//ÎïÀí¼üÅÌ×´Ì¬
		}
		else
		{
			break;
		}
	}
	monitor_run = 0;
	sockMonitorfd = 0;
	return 0;

}

//Ê¹ÄÜ¼üÊó¼à¿Ø  ¶Ë¿ÚºÅÈ¡Öµ·¶Î§ÊÇ1024µ½49151
int kmNet_monitor(short port)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;				//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_monitor;		//Ö¸Áî
	if (port){
		monitor_port = port;				//ÄÇ¸ö¶Ë¿ÚÓÃÀ´¼àÌıÎïÀí¼üÊóÊı¾İ
		tx.head.rand = port | 0xaa55 << 16;	// Ëæ»ú»ìÏıÖµ
	}
	else
		tx.head.rand = 0;	// Ëæ»ú»ìÏıÖµ
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (sockMonitorfd > 0)	//¹Ø±Õ¼àÌı
	{	closesocket(sockMonitorfd);
		sockMonitorfd = 0;
	}
	if (port)
	{
		CreateThread(NULL, 0, ThreadListenProcess, NULL, 0, NULL);
	}
	Sleep(10);//¸øµãÊ±¼äÈÃÏß³ÌÏÈÔËĞĞ
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


/*
¼àÌıÎïÀíÊó±ê×ó¼ü×´Ì¬
·µ»ØÖµ
-1£º»¹Î´¿ªÆô¼àÌı¹¦ÄÜ ĞèÒªÏÈµ÷ÓÃkmNet_monitor£¨1£©
0 :ÎïÀíÊó±ê×ó¼üËÉ¿ª
1£ºÎïÀíÊó±ê×ó¼ü°´ÏÂ
*/
int kmNet_monitor_mouse_left()
{
	if (monitor_run != monitor_ok) return -1;
	return (hw_mouse.buttons & 0x01) ? 1 : 0;
}


/*//¼àÌıÎïÀíÊó±êÖĞ¼ü×´Ì¬
·µ»ØÖµ
-1£º»¹Î´¿ªÆô¼àÌı¹¦ÄÜ ĞèÒªÏÈµ÷ÓÃkmNet_monitor£¨1£©
0 :ÎïÀíÊó±êÖĞ¼üËÉ¿ª
1£ºÎïÀíÊó±êÖĞ¼ü°´ÏÂ
*/
int kmNet_monitor_mouse_middle()
{
	if (monitor_run != monitor_ok) return -1;
	return (hw_mouse.buttons & 0x04) ? 1 : 0;
}

/*//¼àÌıÎïÀíÊó±êÓÒ¼ü×´Ì¬
·µ»ØÖµ
-1£º»¹Î´¿ªÆô¼àÌı¹¦ÄÜ ĞèÒªÏÈµ÷ÓÃkmNet_monitor£¨1£©
0 :ÎïÀíÊó±êÓÒ¼üËÉ¿ª
1£ºÎïÀíÊó±êÓÒ¼ü°´ÏÂ
*/
int kmNet_monitor_mouse_right()
{
	if (monitor_run != monitor_ok) return -1;
	return (hw_mouse.buttons & 0x02) ? 1 : 0;
}


/*//¼àÌıÎïÀíÊó±ê²à¼ü1×´Ì¬
·µ»ØÖµ
-1£º»¹Î´¿ªÆô¼àÌı¹¦ÄÜ ĞèÒªÏÈµ÷ÓÃkmNet_monitor£¨1£©
0 :ÎïÀíÊó±ê²à¼ü1ËÉ¿ª
1£ºÎïÀíÊó±ê²à¼ü1°´ÏÂ
*/
int kmNet_monitor_mouse_side1()
{
	if (monitor_run != monitor_ok) return -1;
	return (hw_mouse.buttons & 0x08) ? 1 : 0;
}

/*//¼àÌıÎïÀíÊó±ê²à¼ü2×´Ì¬
·µ»ØÖµ
-1£º»¹Î´¿ªÆô¼àÌı¹¦ÄÜ ĞèÒªÏÈµ÷ÓÃkmNet_monitor£¨1£©
0 :ÎïÀíÊó±ê²à¼ü2ËÉ¿ª
1£ºÎïÀíÊó±ê²à¼ü2°´ÏÂ
*/
int kmNet_monitor_mouse_side2()
{
	if (monitor_run != monitor_ok) return -1;
	return (hw_mouse.buttons & 0x10) ? 1 : 0;
}



//¼àÌı¼üÅÌÖ¸¶¨°´¼ü×´Ì¬
int kmNet_monitor_keyboard(short  vkey)
{
	unsigned char vk_key = vkey & 0xff;
	if (monitor_run != monitor_ok) return -1;
	if (vk_key >= KEY_LEFTCONTROL && vk_key <= KEY_RIGHT_GUI)//¿ØÖÆ¼ü
	{
		switch (vk_key)
		{
		case KEY_LEFTCONTROL: return  hw_keyboard.buttons & BIT0 ? 1 : 0;
		case KEY_LEFTSHIFT:   return  hw_keyboard.buttons & BIT1 ? 1 : 0;
		case KEY_LEFTALT:     return  hw_keyboard.buttons & BIT2 ? 1 : 0;
		case KEY_LEFT_GUI:    return  hw_keyboard.buttons & BIT3 ? 1 : 0;
		case KEY_RIGHTCONTROL:return  hw_keyboard.buttons & BIT4 ? 1 : 0;
		case KEY_RIGHTSHIFT:  return  hw_keyboard.buttons & BIT5 ? 1 : 0;
		case KEY_RIGHTALT:    return  hw_keyboard.buttons & BIT6 ? 1 : 0;
		case KEY_RIGHT_GUI:   return  hw_keyboard.buttons & BIT7 ? 1 : 0;
		}
	}
	else//³£¹æ¼ü
	{
		for (int i = 0; i < 10; i++)
		{
			if (hw_keyboard.data[i] == vk_key)
			{
				return 1;
			}
		}
	}
	return 0;

}


//¿ªÆôºĞ×ÓÄÚ²¿´òÓ¡ĞÅÏ¢²¢·¢ËÍµ½Ö¸¶¨¶Ë¿Ú£¨µ÷ÊÔÊ¹ÓÃ£©
int kmNet_debug(short port, char enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_debug;			//Ö¸Áî
	tx.head.rand = port | enable << 16;	// Ëæ»ú»ìÏıÖµ
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);

}

//ÆÁ±ÎÊó±ê×ó¼ü 
int kmNet_mask_mouse_left(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT0) : (mask_keyboard_mouse_flag &= ~BIT0);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

//ÆÁ±ÎÊó±êÓÒ¼ü 
int kmNet_mask_mouse_right(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT1) : (mask_keyboard_mouse_flag &= ~BIT1);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÆÁ±ÎÊó±êÖĞ¼ü 
int kmNet_mask_mouse_middle(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT2) : (mask_keyboard_mouse_flag &= ~BIT2);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÆÁ±ÎÊó±ê²à¼ü¼ü1 
int kmNet_mask_mouse_side1(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT3) : (mask_keyboard_mouse_flag &= ~BIT3);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}



//ÆÁ±ÎÊó±ê²à¼ü¼ü2
int kmNet_mask_mouse_side2(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT4) : (mask_keyboard_mouse_flag &= ~BIT4);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÆÁ±ÎÊó±êXÖá×ø±ê
int kmNet_mask_mouse_x(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT5) : (mask_keyboard_mouse_flag &= ~BIT5);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÆÁ±ÎÊó±êyÖá×ø±ê
int kmNet_mask_mouse_y(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT6) : (mask_keyboard_mouse_flag &= ~BIT6);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}

//ÆÁ±ÎÊó±ê¹öÂÖ
int kmNet_mask_mouse_wheel(int enable)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = enable ? (mask_keyboard_mouse_flag |= BIT7) : (mask_keyboard_mouse_flag &= ~BIT7);	// ÆÁ±ÎÊó±ê×ó¼ü
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//ÆÁ±Î¼üÅÌÖ¸¶¨°´¼ü
int kmNet_mask_keyboard(short vkey)
{
	int err;
	BYTE v_key = vkey & 0xff;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_mask_mouse;		//Ö¸Áî
	tx.head.rand = (mask_keyboard_mouse_flag & 0xff) | (v_key << 8);	// ÆÁ±Î¼üÅÌvkey
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//½â³ıÆÁ±Î¼üÅÌÖ¸¶¨°´¼ü
int kmNet_unmask_keyboard(short vkey)
{
	int err;
	BYTE v_key = vkey & 0xff;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_unmask_all;		//Ö¸Áî
	tx.head.rand = (mask_keyboard_mouse_flag & 0xff) | (v_key << 8);	// ÆÁ±Î¼üÅÌvkey
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//½â³ıÆÁ±ÎËùÓĞÒÑ¾­ÉèÖÃµÄÎïÀíÆÁ±Î
int kmNet_unmask_all()
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_unmask_all;		//Ö¸Áî
	mask_keyboard_mouse_flag = 0;
	tx.head.rand = mask_keyboard_mouse_flag;
	int length = sizeof(cmd_head_t);
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}



//ÉèÖÃÅäÖÃĞÅÏ¢  ¸ÄIPÓë¶Ë¿ÚºÅ
int kmNet_setconfig(char* ip, unsigned short port)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	tx.head.indexpts++;					//Ö¸ÁîÍ³¼ÆÖµ
	tx.head.cmd = cmd_setconfig;		//Ö¸Áî
	tx.head.rand = inet_addr(ip); ;
	tx.u8buff.buff[0] = port >> 8;
	tx.u8buff.buff[1] = port >> 0;
	int length = sizeof(cmd_head_t) + 2;
	sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
	SOCKADDR_IN sclient;
	int clen = sizeof(sclient);
	err = recvfrom(sockClientfd, (char*)&rx, 1024, 0, (struct sockaddr*)&sclient, &clen);
	if (err < 0)
		return err_net_rx_timeout;
	return NetRxReturnHandle(&rx, &tx);
}


//½«Õû¸öLCDÆÁÄ»ÓÃÖ¸¶¨ÑÕÉ«Ìî³ä¡£ ÇåÆÁ¿ÉÒÔÓÃºÚÉ«
int kmNet_lcd_color(unsigned short rgb565)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	for (int y = 0; y < 40; y++)
	{
		tx.head.indexpts++;		    //Ö¸ÁîÍ³¼ÆÖµ
		tx.head.cmd = cmd_showpic;	//Ö¸Áî
		tx.head.rand = 0 | y * 4;
		for (int c = 0;c < 512;c++)
			tx.u16buff.buff[c] = rgb565;
		int length = sizeof(cmd_head_t) + 1024;
		sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
		SOCKADDR_IN sclient;
		int clen = sizeof(sclient);
		err = recvfrom(sockClientfd, (char*)&rx, length, 0, (struct sockaddr*)&sclient, &clen);
		if (err < 0)
			return err_net_rx_timeout;
	}
	return NetRxReturnHandle(&rx, &tx);

}

//ÔÚµ×²¿ÏÔÊ¾Ò»ÕÅ128x80µÄÍ¼Æ¬
int kmNet_lcd_picture_bottom(unsigned char* buff_128_80)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	for (int y = 0; y < 20; y++)
	{
		tx.head.indexpts++;		    //Ö¸ÁîÍ³¼ÆÖµ
		tx.head.cmd = cmd_showpic;	//Ö¸Áî
		tx.head.rand = 80 + y * 4;
		memcpy(tx.u8buff.buff, &buff_128_80[y * 1024], 1024);
		int length = sizeof(cmd_head_t) + 1024;
		sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
		SOCKADDR_IN sclient;
		int clen = sizeof(sclient);
		err = recvfrom(sockClientfd, (char*)&rx, length, 0, (struct sockaddr*)&sclient, &clen);
		if (err < 0)
			return err_net_rx_timeout;
	}
	return NetRxReturnHandle(&rx, &tx);
}

//ÔÚµ×²¿ÏÔÊ¾Ò»ÕÅ128x160µÄÍ¼Æ¬
int kmNet_lcd_picture(unsigned char* buff_128_160)
{
	int err;
	if (sockClientfd <= 0)		return err_creat_socket;
	for (int y = 0; y < 40; y++)
	{
		tx.head.indexpts++;		    //Ö¸ÁîÍ³¼ÆÖµ
		tx.head.cmd = cmd_showpic;	//Ö¸Áî
		tx.head.rand = y * 4;
		memcpy(tx.u8buff.buff, &buff_128_160[y * 1024], 1024);
		int length = sizeof(cmd_head_t) + 1024;
		sendto(sockClientfd, (const char*)&tx, length, 0, (struct sockaddr*)&addrSrv, sizeof(addrSrv));
		SOCKADDR_IN sclient;
		int clen = sizeof(sclient);
		err = recvfrom(sockClientfd, (char*)&rx, length, 0, (struct sockaddr*)&sclient, &clen);
		if (err < 0)
			return err_net_rx_timeout;
	}
	return NetRxReturnHandle(&rx, &tx);
}
