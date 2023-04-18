
#include "PublicUtils.h"
#include "NetcardInfo.h"
#include <stdio.h>
#include "FileOper.h"
#include <vector>



int NetcardInfo::getGateway(){

	int ret = 0;
	string fn = "./route.txt";
	ret = system(("rm -rf " + fn).c_str());

	ret = system(("route >> " + fn).c_str());
	if(ret ){
		return -1;
	}

	char * buf;
	int filesize;
	ret =FileOper::fileReader(fn.c_str(),&buf,&filesize);
	if(ret < 0){
		return -1;
	}

	string str = buf;

	string gateway;
	string flag = "default ";
	int pos = str.find(flag);
	if(pos > 0){
		gateway = str.substr(pos + flag.length());

		unsigned int i = 0;
		for( i = 0; i < gateway.length(); i++){
			if(gateway.at(i) == ' '){
				i ++;
			}else{
				break;
			}
		}

		gateway = gateway.substr(i);

		pos = gateway.find(" ");
		if(pos > 0){
			gateway = gateway.substr(0,pos);
			gGatewayIP = inet_addr(gateway.c_str());
			printf("gateway ip:%s\r\n",gateway.c_str());
			return 0;
		}
	}

	return -1;
}



void NetcardInfo::getmacfromstr(const char * mac,unsigned char * dstmac){
	char value[4] = {0};
	int offset = 0;
	for(int i = 0; i < 6; i++){
		memmove(value,mac + offset,2);
		dstmac[i] = strtol(value,0,16);
		offset +=3;
	}
}



int NetcardInfo::getCardInfo(){

	int ret = 0;
	string fn = "./card.txt";
	ret = system(("rm -rf " + fn).c_str());

	ret = system(("ifconfig >> " + fn).c_str());
	if(ret ){
		return -1;
	}

	char * buf;
	int filesize;
	ret =FileOper::fileReader(fn.c_str(),&buf,&filesize);
	if(ret < 0){
		return -1;
	}


	string str = buf;
	vector<string > cardinfo;

	int pos = 0;
	do{
		pos = str.find("\n\n");
		if(pos > 0){
			string substr = str.substr(0,pos);

			cardinfo.push_back(substr);

			str = str.substr(pos + 2);
		}
	}while(pos > 0);


	for(int i = 0; i < cardinfo.size();  i++){
		printf("%u:\t%s\r\n",i,cardinfo[i].c_str());
	}

	int iInterfaceCnt = cardinfo.size();
	int iChooseNum = 0;
	printf("input netcard no you want to attack:(0--%d):", cardinfo.size() -1);
	scanf("%d", &iChooseNum);
	printf("\n");
	if (iChooseNum < 0 || iChooseNum >= iInterfaceCnt)
	{
		printf("Interface number out of range\r\n");
		getchar();
		return -1;
	}

	string info = cardinfo[iChooseNum];

	pos = info.find(":");
	if(pos > 0){
		string cardname = info.substr(0,pos);
		int i =0;
		for( i = 0; i < cardname.length(); i ++){
			if(cardname.at(i) == ' '){
				i ++;
			}else{
				break;
			}
		}

		cardname = cardname.substr(i);
		gNetcardName = cardname;
		printf("cardname:%s\r\n",gNetcardName.c_str());
	}


	string netmaskflag = " netmask ";
	string netmask ;
	pos = info.find(netmaskflag);
	if(pos > 0){
		netmask = info.substr(pos + netmaskflag.length());
		pos = netmask.find(" ");
		if(pos > 0){
			netmask = netmask.substr(0,pos);
			gNetMask = inet_addr(netmask.c_str());
			printf("netmask:%s",netmask.c_str());
		}
	}


	string mac;
	string etherflag = " ether ";
	pos = info.find(etherflag);
	if(pos > 0){
		mac = info.substr(pos + etherflag.length());
		pos = mac.find(" ");
		if(pos > 0){
			mac = mac.substr(0,pos);
			printf("mac:%s\r\n",mac.c_str());
			//unsigned char lpmac[256];
			//ret = sscanf(mac.c_str(),"%2d:%2d:%2d:%2d:%2d:%2d",(unsigned int*)&lpmac[0],(unsigned int*)&lpmac[1],(unsigned int*)&lpmac[2],
			//		(unsigned int*)&lpmac[3],(unsigned int*)&lpmac[4],(unsigned int*)&lpmac[5]);
			//memmove(gLocalMAC,lpmac,MAC_ADDRESS_SIZE);

			getmacfromstr(mac.c_str(),gGatewayMAC);
		}
	}


	string ip;
	string ipflag = " inet ";
	pos = info.find(ipflag);
	if(pos > 0){
		ip = info.substr(pos + ipflag.length());
		pos = ip.find(" ");
		if(pos > 0){
			ip = ip.substr(0,pos);
			gLocalIP = inet_addr(ip.c_str());
			printf("ip:%s\r\n",ip.c_str());
		}
	}


//	string value = mac;
//	do{
//		string tmp
//		pos = value.find(":");
//		if(pos > 0){
//
//		}
//	}

	return 0;
}




/*
ifaddrs * NetcardInfo::getIFADDRSPointer(int * iCounter) {
	struct sockaddr_in *sin = NULL;
	struct ifaddrs *ifa = NULL, *ifList = NULL;

	if (getifaddrs(&ifList) < 0)
	{
		printf("getifaddrs error\r\n");
		return 0;
	}

	for (ifa = ifList, *iCounter = 0; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(strcmp(ifa->ifa_name,"lo") == 0){
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET)
		{

			sin = (struct sockaddr_in *)ifa->ifa_addr;
			string ip = inet_ntoa(sin->sin_addr);

			sin = (struct sockaddr_in *)ifa->ifa_dstaddr;
			string broadip= inet_ntoa(sin->sin_addr);

			sin = (struct sockaddr_in *)ifa->ifa_netmask;
			string netmask = inet_ntoa(sin->sin_addr);

			printf("%u Name:%s,IP:%s,Broadcast IP:%s,Netmask:%s\r\n", *iCounter, ifa->ifa_name, ip.c_str(),broadip.c_str(),netmask.c_str());
			(*iCounter) ++;
		}
	}

	return ifList;
}


ifaddrs * NetcardInfo::setIFADDRSPointer(struct ifaddrs *ifList,int seq) {
	struct ifaddrs *ifa = NULL;
	int i = 0;
	for (ifa = ifList; i < seq; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			i++;
		}
	}

	return ifa;

}
*/





















