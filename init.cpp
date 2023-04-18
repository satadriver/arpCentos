/*
 * init.cpp
 *
 *  Created on: Sep 8, 2018
 *      Author: root
 */

#include "init.h"
#include "ClientAddress.h"
#include <signal.h>
#include "NetcardInfo.h"
#include "NetParam.h"
#include "ethtool.h"
#include "ArpSniffer.h"
#include "Log.h"


int init::initSignal(){
	//SIG_IGN 屏蔽该信号
	//SIG_DFL 恢复默认行为
	__sighandler_t handler = signal(SIGPIPE,SIG_IGN);
	if( handler == SIG_ERR){
		printf("signal error\r\n");
		return -1;
	}
    sigset_t signal_mask;
    sigemptyset (&signal_mask);
    sigaddset (&signal_mask, SIGPIPE);
    int rc = pthread_sigmask (SIG_BLOCK, &signal_mask, NULL);
    if (rc != 0) {
        printf("block sigpipe error\n");
        return -1;
    }

    return 0;
}


int init::initNetwork(){
	int ret = 0;

	ret = init::initSignal();
	ret = system("systemctl stop firewalld");
	ret = system("systemctl disable firewalld");

	ret = NetParam::getLocalNetParams();

	gCardIdx = if_nametoindex(gNetcardName.c_str());
	if(gCardIdx == 0 )
	{
		printf("if_nametoindex() failed to obtain interface index\n");
		return -1;
	}else{

		printf("index of interface %s is %u\n",gNetcardName.c_str(),gCardIdx);
	}

	ret = NetParam::getGatewayFromArp();

    //ret = ClientAddress::getMACFromIP(gGatewayIP,gGatewayMAC);

    in_addr nm;
    in_addr nmip;
    in_addr gip;
    nm.s_addr = gNetMask;
    nmip.s_addr = gNetMaskIP;
    gip.s_addr = gGatewayIP;
    char * lpnm = inet_ntoa(nm);
    printf("net mask:%s\r\n",lpnm);
    char * lpnmip = inet_ntoa(nmip);
    printf("net maskip:%s\r\n",lpnmip);
    char * lpgip = inet_ntoa(gip);
    printf("gatewayip:%s\r\n",lpgip);

    ret = NetParam::makemtu();

    ret = ethtool::closeall();

    return ret;

//	int iInterfaceCnt = 0;
//	int iChooseNum = 0;
//
//	struct ifaddrs *ifList = NetcardInfo::getIFADDRSPointer(&iInterfaceCnt);
//	printf("input netcard no you want to attack:(0--%d):", iInterfaceCnt - 1);
//	scanf("%d", &iChooseNum);
//	printf("\n");
//	if (iChooseNum < 0 || iChooseNum >= iInterfaceCnt)
//	{
//		printf("Interface number out of range\r\n");
//		getchar();
//		return -1;
//	}
//
//	struct ifaddrs * ifa = NetcardInfo::setIFADDRSPointer(ifList,iChooseNum);
//
//	struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
//
//	gLocalIP =sin->sin_addr.s_addr;
//
//	gNetcardName = ifa->ifa_name;
//
//	freeifaddrs(ifList);
//	printf("dns hijack local address ip:%s\r\n", inet_ntoa(sin->sin_addr));
}



