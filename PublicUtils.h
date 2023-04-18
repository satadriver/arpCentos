#pragma once


#ifndef PUBLICUTILS_H_H_H
#define PUBLICUTILS_H_H_H


#include <iostream>

#include <string>
#include <sys/stat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

//#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>


//extern "C" {
#include <map>
#include <vector>
#include <iostream>
#include <string>
#include <unordered_map>
//}





#pragma pack(1)

using namespace std;

#define CENTOS
//#define ANDROID
#ifdef CENTOS
#define TMP_SELECTED_NETCARD_NAME "enp2s0"
#define CONFIG_FILENAME "./config.ini"
#else
using namespace std::tr1;
#define TMP_SELECTED_NETCARD_NAME "wlan0"
#define CONFIG_FILENAME "/sdcard/config.ini"
#endif

#define MAX_PATH 1024
#define MAC_ADDRESS_SIZE 6
#define TRUE 1
#define FALSE 0
#define DWORD unsigned int
#define USHORT unsigned short
#define WORD unsigned short
#define UCHAR unsigned char



#define CRLN 								"\n"

#define MTU									1500
#define MAC_ADDRESS_SIZE					6	

#define MIN_PROXYPORT_VALUE 0xff00
#define MAX_PROXYPORT_VALUE 0xffff

#define ZEROMACADDRESS						"\x00\x00\x00\x00\x00\x00"
#define BROADCASTMACADDRESS					"\xff\xff\xff\xff\xff\xff"

#define BROADCAST_MAC_ADDRESS				"\x0ff\x0ff\x0ff\x0ff\x0ff\x0ff"
#define ZERO_MAC_ADDRESS					"\x00\x00\x00\x00\x00\x00"



typedef struct
{
	unsigned char clientMAC[MAC_ADDRESS_SIZE];
	unsigned int clientIP;
	unsigned short clientPort;
	time_t time;
}CLIENTADDRESSES, *LPCLIENTADDRESSES;

typedef struct {
	unsigned int serverIP;
	unsigned short serverPort;
	unsigned int clientIP;
	unsigned short clientPort;
}MAPSOCKETKEY, *LPMAPSOCKETKEY;


#define MAP_TRAVERSAL_SECONDS 360

#define ARP_QUERY_TIMEDELAY 300

#define ARP_FIRSTSCAN_TIMEDELAY 1

#define PACKET_RECV_BUF_SIZE 4096
#define ARP_SCAN_TIMEDELAY 6

extern int gArpDelay;

extern string gNetcardName;

extern unsigned int gNetMask;

extern unsigned int gNetMaskIP;

extern unsigned int gGatewayIP;

extern unsigned int gLocalIP;

extern unsigned char gGatewayMAC[MAC_ADDRESS_SIZE];

extern unsigned char gLocalMAC[MAC_ADDRESS_SIZE];

extern LPCLIENTADDRESSES gClientAddress;

extern int gCardIdx;

extern vector < CLIENTADDRESSES> gAttackTarget;

extern vector <CLIENTADDRESSES> gOnlineObjects;

extern unsigned int gFakeProxyIP;

extern string log_tag;



#endif
