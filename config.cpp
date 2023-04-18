/*
 * config.cpp
 *
 *  Created on: Nov 12, 2018
 *      Author: root
 */







#include "config.h"
#include "FileOper.h"
#include "Public.h"
#include "PublicUtils.h"
#include "ClientAddress.h"

#include <vector>
#include <iostream>
#include <string>
#include "Public.h"


using namespace std;

int Config::addTarget(unsigned int ip,vector<CLIENTADDRESSES>&attackList) {
	int ret = 0;

	unsigned char mac[MAC_ADDRESS_SIZE];
	ret = ClientAddress::getMACFromIP(ip, mac);
	if (ret == 0)
	{
		ret = addTarget(attackList, ip, mac);
	}

	return ret;
}


int Config::addTarget(vector<CLIENTADDRESSES> & targets,unsigned int ip,unsigned char mac[MAC_ADDRESS_SIZE]) {

	if (ip == gLocalIP || ip == gGatewayIP || ((ntohl(ip) & 0xff) == 0) || ((ntohl(ip) & 0xff) == 0xff) )
	{
		return -1;
	}

	for (unsigned int i = 0; i < targets.size(); i++)
	{
		if (targets[i].clientIP == ip)
		{
			return -1;
		}
	}


	CLIENTADDRESSES ca = { 0 };
	ca.clientIP = ip;
	memmove(ca.clientMAC, mac, MAC_ADDRESS_SIZE);
	targets.push_back(ca);

	string strip = Public::formatIP(ca.clientIP);
	string strmac = Public::formatMAC(ca.clientMAC);
	printf("add attack ip:%s,mac:%s\r\n", strip.c_str(), strmac.c_str());

	return 0;

}


int Config::getAttackTarget(string fn,vector<CLIENTADDRESSES> & targets,unsigned int * fakeip,int * arprepeat) {
	int ret = 0;
	char * buf = 0;
	int fs = 0;

	ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret < 0) {
		printf("fopen config file:%s error\r\n",fn.c_str());
		return -1;
	}

	int cfglen = Public::removespace(buf, buf);
	string str = string(buf, cfglen);
	delete buf;

	string substr = "";
	int flag = 0;
	while (1) {
		int linepos = str.find(CRLN);
		if (linepos >= 0) {
			substr = str.substr(0, linepos);
		}
		else {
			substr = str;
			flag = 1;
		}

		const char* end = 0;
		const char* hdr = 0;

		char * arpdelayhdr = "arprepeat=";
		char * fakeiphdr = "fakeip=";

		hdr = strstr(substr.c_str(), "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {

				string value = string(hdr, end - hdr);
				if (strcmp(value.c_str(),"alls") == 0)
				{
					targets = gOnlineObjects;
					printf("crazy mode start!\r\n");
					return targets.size();
				}else if (memcmp(value.c_str(), fakeiphdr,strlen(fakeiphdr)) == 0)
				{
					string strfakeip = value.substr(strlen(fakeiphdr));
					*fakeip = inet_addr(strfakeip.c_str());
					printf("set winpcap fakeip:%s\r\n", strfakeip.c_str());
				}
				else if (memcmp(value.c_str(), arpdelayhdr, strlen(arpdelayhdr)) == 0)
				{
					string strarpdelay = value.substr(strlen(arpdelayhdr));
					*arprepeat = atoi(strarpdelay.c_str());
					printf("set arp repeat speed:%d seconds\r\n", *arprepeat);
				}
				else {
					printf("get ip:%s from config file\r\n",value.c_str());
					unsigned int ip = inet_addr(value.c_str());
					if (ip != 0 && ip!= 0xffffffff)
					{
						ret = addTarget(ip, targets);
					}
				}
			}
		}

		if (flag > 0) {
			break;
		}

		str = str.substr(linepos + 1);
		continue;
	}

	return targets.size();
}







int Config::getAttackTargetFromCmd(char * buf, vector<CLIENTADDRESSES> & targets) {

	int ret = 0;
	int cfglen = Public::removespace(buf, buf);
	string str = string(buf, cfglen);

	string substr = "";
	int flag = 0;
	while (1) {
		int linepos = str.find(",");
		if (linepos >= 0) {
			substr = str.substr(0, linepos);
		}
		else {
			substr = str;
			flag = 1;
		}

		string value = substr;
		if (strcmp(value.c_str(), "alls") == 0)
		{
			targets = gOnlineObjects;
			printf("crazy mode start!\r\n");
			return targets.size();
		}
		else {
			unsigned int ip = inet_addr(value.c_str());
			if (ip != 0 && ip != 0xffffffff)
			{
				ret = addTarget(ip, targets);
			}
		}

		if (flag > 0) {
			break;
		}

		str = str.substr(linepos + 1);
		continue;
	}

	return targets.size();
}


int Config::getSubnetSize() {
	return ntohl(~gNetMask) + 1;
}


unsigned int Config::getProxyIP(vector<CLIENTADDRESSES> targets){

	int cnt =  Config::getSubnetSize();

	for(int i = 0 ; i < cnt; i ++){
		unsigned int ip = ntohl(ntohl(gNetMaskIP) + i);

		if(i == 0 || i == 0xff || ip == gLocalIP || ip == gGatewayIP){
			continue;
		}

		unsigned int j = 0;
		for ( ; j < targets.size(); j++)
		{
			if (targets[j].clientIP == ip)
			{
				break;
			}
		}

		if(j >= targets.size()){
			return ip;
		}

	}
	return -1;
}
