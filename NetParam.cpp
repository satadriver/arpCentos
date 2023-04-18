
#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <limits.h>
#include <ctype.h>
#include <linux/sockios.h>
#include <net/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include "NetParam.h"
#include <sys/socket.h>

#include "PublicUtils.h"
#include "FileOper.h"
#include "NetcardInfo.h"

using namespace std;





int NetParam::getLocalNetParams()
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("getLocalNetInfo socket");
		close(fd);
		return -1;
	}

	struct ifreq buf[64];
	struct ifconf ifc;


	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;
	if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) == 0)
	{
       char mac[64] = {0};
	   char ip[64] = {0};
	   char broadAddr[64] = {0};
	   char subnetMask[64] = {0};
	   int interfaceNum = 0;
	   interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
	   printf("find net card interface total count:%d\n", interfaceNum);

	   while (interfaceNum-- > 0)
	   {
		   string cardname = string(buf[interfaceNum].ifr_name);

		   printf("net card device name:%s\n", cardname.c_str());

		   int pos = cardname.find("lo");
		   if( pos >= 0){
			   printf("find and ignore lo\r\n");
			   continue;
		   }

		   pos = cardname.find(TMP_SELECTED_NETCARD_NAME);
		   if(pos < 0){
			   //printf("not wlan0,ignore it\r\n");
			   continue;
		   }else{
			   printf("find wlan0\r\n");
		   }

		   gNetcardName = cardname;

		  //ignore the interface that not up or not runing
		  struct ifreq ifrcopy = buf[interfaceNum];
       	  if (ioctl(fd, SIOCGIFFLAGS, &ifrcopy))
       	  {
       		  printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
       		  close(fd);
       		  return -1;
       	  }

       	  if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
       	  {
       		  memmove(gLocalMAC ,buf[interfaceNum].ifr_hwaddr.sa_data,MAC_ADDRESS_SIZE);

       		  memset(mac, 0, sizeof(mac));
       		  snprintf(mac, sizeof(mac), "%02x%02x%02x%02x%02x%02x",
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
							(unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);
       		  printf("device mac: %s\n", mac);
       	  }
       	  else
       	  {
       		  printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
       		  close(fd);
       		  return -1;
       	  }

       	  if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[interfaceNum]))
       	  {
       		  gLocalIP = ((struct sockaddr_in *)&(buf[interfaceNum].ifr_addr))->sin_addr.s_addr;
       		  snprintf(ip, sizeof(ip), "%s",(char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_addr))->sin_addr));
       		  printf("device ip: %s\n", ip);
       	  }
       	  else
       	  {
       		  printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
       		  close(fd);
       		  return -1;
       	  }

       	  if (!ioctl(fd, SIOCGIFBRDADDR, &buf[interfaceNum]))
       	  {
       		  snprintf(broadAddr, sizeof(broadAddr), "%s",(char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_broadaddr))->sin_addr));
       		  printf("device broadAddr: %s\n", broadAddr);
       	  }
       	  else
       	  {
       		  printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
       		  close(fd);
			  return -1;
       	  }

       	  if (!ioctl(fd, SIOCGIFNETMASK, &buf[interfaceNum]))
       	  {

       		  gNetMask = ((struct sockaddr_in *)&(buf[interfaceNum].ifr_netmask))->sin_addr.s_addr;

       		  //in_addr ia;
       		  //ia.s_addr = gNetMask;
       		  //printf("i get netmask:%s\r\n",inet_ntoa(ia));

       		  if(gNetMask == 0xffff || gNetMask == 0xffff0000){
       			  gNetMask = 0xffffff;
       		  }

       		  snprintf(subnetMask, sizeof(subnetMask), "%s", (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_netmask))->sin_addr));
       		  printf("device subnetMask: %s\n", subnetMask);
       	  }
       	  else
       	  {
       		  printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
       		  close(fd);
       		  return -1;
       	  }
      }

    }
    else
    {
        printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
        close(fd);
        return -1;
    }

   close(fd);
   return 0;
}




int splitstr(char * str,char dst[32][256]){
	int len = strlen(str);
	for(int i = 0; i< len; i ++){
		if(str[i] == ' '){
			str[i] = 0;
		}
	}

	int j =0;
	for(int i = 0; i < len; ) {
		if(str[i] != 0){
			strcpy(dst[j],&str[i]);
			j ++;
			i += strlen(&str[i]);
		}else{
			i ++;
		}
	}

	return j;
}



int splitstring(string str,string strarray[256]){

	int i = 0;
	while(1){
		int pos = str.find("\n");
		if(pos ==-1){
			if(str.length() > 0){
				strarray[i] = str;
				i ++;
			}
			return i;
		}else{
			strarray[i] = str.substr(0,pos);
			i ++;
			str = str.substr(pos + 1);
		}
	}

	return i;
}



int NetParam::getGatewayFromArp(){
	int ret = 0;
	char * szbuf;
	int filesize = 0;
	ret = FileOper::devfReader(string("/proc/net/arp"),&szbuf,&filesize);
	if(ret < 0){
		printf("get /proc/net/arp error\r\n");
		return -1;
	}else{
		printf("get local machine /proc/net/arp :%s\r\n",szbuf);
	}
	string str = string(szbuf);
	delete [] szbuf;

	int pos = str.find("\n");
	if(pos == -1){
		printf("not found gateway info\r\n");
		return -1;
	}

	string name = str.substr(0,pos);
	string arpvalue = str.substr(pos + 1);
	string strarray[256] = {""};
	int strcnt = splitstring(arpvalue,strarray);

	for(int i = 0; i < strcnt ; i ++){
		printf("string[%u]:%s\r\n",i,strarray[i].c_str());
	}

	string gw = "";
	for( int i = 0; i < strcnt; i ++){
		pos = strarray[i].find(TMP_SELECTED_NETCARD_NAME);
		if(pos == -1){
			printf("not found wlan0 info\r\n");
			return -1;
		}

		pos = strarray[i].find(" ");
		if(pos < 0){
			return -1;
		}

		if(strcnt == 1){
			gw = strarray[i];
			break;
		}else{
			string strip = strarray[i].substr(0,pos);
			printf("tmpip:%s\r\n",strip.c_str());
			unsigned int intip = inet_addr(strip.c_str());
			if((ntohl(intip) & 0xff) == 1){
				gw = strarray[i];
				break;
			}
		}
	}

	printf("gateway info:%s\r\n",gw.c_str());
	char szvalue[1024];
	strcpy(szvalue,gw.c_str());

	char allvalue[32][256];
	int cnt = splitstr(szvalue,allvalue);
	if(cnt >= 6){
		gGatewayIP = inet_addr(allvalue[0]);

		//gNetMask = 0xffffff;
		gNetMaskIP = gNetMask & gGatewayIP;

		in_addr ia;
		ia.s_addr = gGatewayIP;
		printf("gate way ip:%s\r\n",inet_ntoa(ia));

		NetcardInfo::getmacfromstr(allvalue[3],gGatewayMAC);

		printf("gate way mac:%s\r\n",allvalue[3]);

	}else{
		return  -1;
	}

	return 0;
}




int NetParam::makemtu(){

	int ret = 0;

	char szfilename[1024];
	ret = sprintf(szfilename,"/sys/class/net/%s/mtu",gNetcardName.c_str());

	char szcmd[1024];
	sprintf(szcmd,"echo \"%u\" > /sys/class/net/%s/mtu",MTU,gNetcardName.c_str());
	ret = system(szcmd);


	char * szbuf;
	int filesize;
	ret = FileOper::fileReader(szfilename,&szbuf,&filesize);
	if(ret <=0){
		return -1;
	}

	printf("set local machine mtu:%s\r\n",szbuf);
	return 0;
}

/*
int NetParam::makemtu(){
	int ret = 0;
	///sys/class/net/wlan0/mtu
	char szcmd[1024];
	ret = sprintf(szcmd,"ifconfig wlan0 mtu %u",MTU);
	ret = system(szcmd);
	ret = system("cat /sys/class/net/wlan0/mtu > /data/local/tmp/mtu");
	char * buf;
	int filesize = 0;
	ret = FileOper::fileReader("/data/local/tmp/mtu",&buf,&filesize);
	if(ret <= 0){
		return -1;
	}

	string str = string(buf);
	printf("local phone mtu:%s\r\n",str.c_str());
	return 0;
}

*/













