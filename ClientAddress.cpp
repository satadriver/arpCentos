
#pragma pack(1)

#include "ClientAddress.h"
#include "PublicUtils.h"
#include "ArpCheat.h"
#include "FileOper.h"
#include "Public.h"

using namespace std;



LPCLIENTADDRESSES gClientAddress;


int ClientAddress::add(CLIENTADDRESSES ca) {
	int offset = ntohl(ca.clientIP) & (~ntohl(gNetMask));
	gClientAddress[offset] = ca;
	return offset;
}



int ClientAddress::del(CLIENTADDRESSES ca) {
	int offset = ntohl(ca.clientIP) & (~ntohl(gNetMask));
	//gClientAddress[offset] = { 0 };

	return offset;
}



int ClientAddress::initClientAddress() {
	int cnt =  ~ntohl(gNetMask) + 1;
	int size = cnt * sizeof(CLIENTADDRESSES);
	if (gClientAddress != 0)
	{
		delete gClientAddress;
	}
	gClientAddress = (LPCLIENTADDRESSES) new char[size];
	memset(gClientAddress, 0, size);

	return cnt;
}







int ClientAddress::getMACFromIP(unsigned int ip, unsigned char mac[MAC_ADDRESS_SIZE]) {

	int nRetCode = ArpCheat::sendArp(ip, mac);
	if (nRetCode != 0)
	{
		printf("getMACFromIP failed ip:%08x\r\n",ip);
		return -1;
	}
 	return 0;
}


int ClientAddress::init() {
	vector<string> target = parseAttackTarget(CONFIG_FILENAME);

	int cnt = 0;
	for(unsigned int i = 0; i < target.size(); i ++){

		unsigned int intip = inet_addr(target[i].c_str());

		CLIENTADDRESSES ca = { 0 };
		ca.clientIP = intip;
		ca.time = time(0);
		int ret = ClientAddress::getMACFromIP(intip, ca.clientMAC);
		if(ret == 0){
			add(ca);

			cnt++;
		}
	}

	//string str = getAttackTarget();
	//int cnt = parseAddIP(str);
	return cnt;
}





string ClientAddress::getAttackTarget() {

	return "192.168.10.183";
	//return "172.26.160.6";
}



int ClientAddress::parseAddIP(string ip) {
	string tmp = ip;

	int cnt = 0;

	do
	{
		int end = tmp.find(",");
		if (end == -1 && tmp.length() > 0)
		{
			unsigned int intip = inet_addr(tmp.c_str());

			CLIENTADDRESSES ca = { 0 };
			ca.clientIP = intip;
			ca.time = time(0);
			int ret = ClientAddress::getMACFromIP(intip, ca.clientMAC);
			if(ret == 0){
				add(ca);
				cnt++;
			}

			return cnt;
		}
		else {
			string tmpip = tmp.substr(0, end);
			int intip = inet_addr(tmpip.c_str());

			CLIENTADDRESSES ca = { 0 };
			ca.clientIP = intip;
			ca.time = time(0);
			int ret = ClientAddress::getMACFromIP(intip, ca.clientMAC);
			if(ret == 0){
				add(ca);

				cnt++;
			}

			tmp = tmp.substr(end + 1);
		}
	} while (1);

	return cnt;
}



vector<string> ClientAddress::parseAttackTarget(string fn){
	char * buf = 0;
	int fs = 0;

	vector <string> DnsAttackList;

	int ret = FileOper::fileReader(fn,&buf,&fs);
	if(ret < 0){
		return DnsAttackList;
	}

	int cfglen = Public::removespace(buf,buf);
	string str = string(buf,cfglen);
	delete buf;

	string substr = "";
	int flag = 0;
	while(1){


		int linepos = str.find("\n");
		if(linepos >= 0){
			substr = str.substr(0,linepos);
		}else{
			substr = str;
			flag = 1;
		}

		const char* end = 0;
		const char* hdr = 0;

		hdr = strstr(substr.c_str(),"[");
		if(hdr >0){
			hdr += strlen("[");
			end = strstr(hdr,"]");
			if(end > 0 && (end - hdr > 0) ){

				string dns = string(hdr,end - hdr);

				DnsAttackList.push_back(dns);

			}
		}

		if(flag > 0){
			break;
		}

		str = str.substr(linepos + 1);
		continue;
	}

	return DnsAttackList;

}





unsigned char* ClientAddress::isTarget(unsigned int ip) {
	int cnt = gAttackTarget.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTarget[i].clientIP == 0 || memcmp(gAttackTarget[i].clientMAC,ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0)
		{
			continue;
		}

		if (ip == gAttackTarget[i].clientIP)
		{
			return gAttackTarget[i].clientMAC;
		}
	}

	return FALSE;
}



unsigned int ClientAddress::isTarget(unsigned char mac[MAC_ADDRESS_SIZE]) {
	int cnt = gAttackTarget.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTarget[i].clientIP == 0 || memcmp(gAttackTarget[i].clientMAC, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0)
		{
			continue;
		}

		if (memcmp(mac, gAttackTarget[i].clientMAC,MAC_ADDRESS_SIZE) == 0)
		{
			return gAttackTarget[i].clientIP;
		}
	}

	return FALSE;
}
