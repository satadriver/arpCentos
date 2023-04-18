#pragma once

#ifndef ARPCHEAT_H_H_H
#define ARPCHEAT_H_H_H


#include "PublicUtils.h"
#include <vector>
#include <iostream>
#include <string>

using namespace std;

class ArpCheat {
public:

	static int sendArp(unsigned int dstip,unsigned char * dstmac);

	static void* ArpCheatProc(void * param);

	static int arpSnifferOneTime(vector<CLIENTADDRESSES> & targetslist);

	static int makeFakeClient(int fd,int index,unsigned int ip,unsigned char mac[MAC_ADDRESS_SIZE]);
	static int sendRarps(int fd,int index);

	static int broadcastArp(int fd,int index, unsigned int ip) ;
	static int arpReply(int fd,int index, unsigned int senederip, unsigned char sendermac[MAC_ADDRESS_SIZE],unsigned int recverip,unsigned char * recvermac);

};

#endif
