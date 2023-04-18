
#include "PublicUtils.h"



string gNetcardName;

unsigned int gGatewayIP;

unsigned int gLocalIP;

unsigned char gGatewayMAC[MAC_ADDRESS_SIZE];

unsigned char gLocalMAC[MAC_ADDRESS_SIZE];

unsigned int gNetMask;

unsigned int gNetMaskIP;

vector < CLIENTADDRESSES> gAttackTarget;
vector <CLIENTADDRESSES> gOnlineObjects;

unsigned int gFakeProxyIP = 0;

int gCardIdx = 0;

int gArpDelay = 30;


