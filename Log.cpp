
#include "Log.h"

#include "FileOper.h"


string TAG = "Android_Arp_Attack";

void Log::log(string str){

	logout(str);
	logFile(str);
}



void Log::logout(string str){
	//__android_log_print(ANDROID_LOG_ERROR,TAG.c_str(),"%s",str.c_str());
}


void Log::logFile(string str){

	int ret = FileOper::fileWriter("/sdcard/android_arp_attack.txt",str.c_str(),str.length());
	return;
}
