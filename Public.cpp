


#include <stdio.h>
#include "Public.h"
#include "PublicUtils.h"


string Public::getPath(){
	char localPath[1024] = {0};
	getcwd(localPath,sizeof(localPath));

	string path = string(localPath) + "/";
	return path;
}




string Public::formatIP(unsigned int ip) {
	unsigned char cip[sizeof(unsigned int)];
	memmove(cip, &ip, sizeof(unsigned int));
	char szip[256];
	sprintf(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);
	return szip;
}


string Public::formatMAC(unsigned char mac[MAC_ADDRESS_SIZE]) {

	char szmac[256];
	sprintf(szmac, "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return szmac;
}




DWORD Public::GetLocalIpAddress()
{
	char local[MAX_PATH] = {0};
	int iRet = gethostname(local, sizeof(local));
	if (iRet )
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = {0};
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr)); 
	if (addr.s_addr == 0)
	{
		return FALSE;
	}
	return addr.s_addr;
}




DWORD Public::GetSubNet(char * szIP,char * szSubNet){

	char * pHdr = szIP;
	char * pEnd = szIP;

	pHdr = strstr(pHdr,".");
	if (pHdr == FALSE)
	{
		return FALSE;
	}
	pHdr += 1;

	pHdr = strstr(pHdr,".");
	if (pHdr == FALSE)
	{
		return FALSE;
	}
	pHdr += 1;

	pEnd = strstr(pHdr,".");
	if (pEnd == FALSE)
	{
		return FALSE;
	}

	memmove(szSubNet,pHdr,pEnd - pHdr);
	return TRUE;
}



int Public::removespace(char * src,char * dst)
{
	int len = strlen(src);
	int i = 0,j = 0;
	for(;i < len; i ++){
		if(src[i] == ' ' || src[i] == 0x9){
			continue;
		}else{
			dst[j] = src[i];
			j ++;
		}
	}
	*(dst + j) = 0;
	return j;
}



int Public::writeLog(char * szFileName,unsigned char * strBuffer,int iCounter)
{
	int iRet = 0;
	FILE * fp = fopen(szFileName,"ab+");
	if (fp > 0 )
	{
		unsigned long ulFileSize = fseek(fp,0,SEEK_END);
		iRet = fwrite(strBuffer,1,iCounter,fp);
		fclose(fp);
		if (iRet != iCounter)
		{

			printf("writeLog error\r\n");
			return FALSE;
		}
		return TRUE;
	}
	else if (fp <= 0)
	{
		perror("writeLog fopen");
	}
	return FALSE;
}
