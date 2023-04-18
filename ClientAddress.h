#pragma once

#ifndef CLIENTADDRESS_H_H_H
#define CLIENTADDRESS_H_H_H


#pragma pack(1)

//#include <list>

#include <vector>

#include "PublicUtils.h"

using namespace std;








class  ClientAddress{
public:
	static vector<string> parseAttackTarget(string fn);
	static int getMACFromIP(unsigned int ip,unsigned char mac[MAC_ADDRESS_SIZE]);

	static int add(CLIENTADDRESSES ca);
	static int del(CLIENTADDRESSES ca);
	static int initClientAddress();
	static int init();
	static string getAttackTarget();
	static int parseAddIP(string ip);

	static unsigned int isTarget(unsigned char mac[MAC_ADDRESS_SIZE]);
	static unsigned char* isTarget(unsigned int ip);

};

#endif
