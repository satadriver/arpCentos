
#pragma once
#ifndef PUBLIC_H_H_H
#define PUBLIC_H_H_H

#include "PublicUtils.h"


class Public{
public:
	static string getPath();
	static string formatIP(unsigned int);
	static string formatMAC(unsigned char mac[MAC_ADDRESS_SIZE]);

	static DWORD GetSubNet(char * szIP,char * szSubNet);
	static int GetNetCardInfo(DWORD * dwIP,char * lpMac,char * szNetIP,DWORD * dwGateWayIP,char * lpGateWayMac);
	static DWORD GetLocalIpAddress();
	static int writeLog(char * pFileName,unsigned char * pData,int dwDataSize);

	static int RecordInFile(char * szFileName,unsigned char * strBuffer,int iCounter);
	static int removespace(char * src,char * dst);
};


#endif
