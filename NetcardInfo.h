#pragma once

#include "PublicUtils.h"






class NetcardInfo {
public:
	static int getGateway();
	static int getCardInfo();
	static void getmacfromstr(const char * mac,unsigned char * dstmac);

	//static ifaddrs * getIFADDRSPointer(int * no);
	//static ifaddrs * setIFADDRSPointer(struct ifaddrs *,int seq);
};



