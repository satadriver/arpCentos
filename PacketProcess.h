#ifndef PACKETPROCESS_H_H_H
#define PACKETPROCESS_H_H_H


#pragma once




#include "Packet.h"
#include "PublicUtils.h"
#include "ClientAddress.h"
#include "FileOper.h"
#include "Public.h"
#include "Packet.h"

extern "C" {

}





using namespace std;



class PacketProcess {
public:

	static void *SnifferPacket(void * param);
	static LPCLIENTADDRESSES getClientIP(unsigned int serverip,unsigned short serverport,unsigned short clientport);

	static unsigned short CalcChecksum(unsigned short *buffer, int size);

	static USHORT GetSubPacketCheckSum(unsigned char * lpCheckSumData, unsigned int checkSumSize, DWORD dwSrcIP, DWORD dwDstIP, unsigned int protocol);

	static void * clearmap(void * param);

};





#endif
