/*
 * ArpSniffer.cpp
 *
 *  Created on: Sep 8, 2018
 *      Author: root
 */


#include "ArpSniffer.h"
#include "ClientAddress.h"
#include "ArpCheat.h"
#include "config.h"






void * ArpSniffer::getHostNext(void * param){

	int sockfd = (unsigned long)param;
	int ret = 0;
	int counter = 0;

	while(1){

		int cnt =  ~ntohl(gNetMask) + 1;

		for(int i = 0 ; i < cnt; i ++){

			unsigned int startip = ntohl(ntohl(gNetMaskIP) + i);

			if(i == 0 || i == 0xff || startip == gLocalIP || startip == gGatewayIP){
				continue;
			}

			ret = ArpCheat::broadcastArp(sockfd,gCardIdx,startip );
		}

		sleep(ARP_QUERY_TIMEDELAY);
	}

	return param;
}








int ArpSniffer::getHost(){
	int ret = 0;

	int counter = 0;

	int cnt =  Config::getSubnetSize();

	for(int i = 0 ; i < cnt; i ++){
		unsigned int startip = ntohl(ntohl(gNetMaskIP) + i);

		if(i == 0 || i == 0xff || startip == gLocalIP || startip == gGatewayIP){
			continue;
		}

		ret = Config::addTarget(startip,gOnlineObjects);

//		CLIENTADDRESSES ca = { 0 };
//		ret = ArpCheat::sendArp(startip , ca.clientMAC);
//		if(ret == 0){
//			ca.clientIP = startip;
//			ca.time = time(0);
//			ClientAddress::add(ca);
//			counter++;
//		}
	}

	return counter;
}



