/*
 * ethtool.cpp
 *
 *  Created on: Sep 8, 2018
 *      Author: root
 */




#include "ethtool.h"

int ethtool::closeall(){
	int ret = gro(false);
	ret = lro(false);
	ret = tso(false);
	ret = ufo(false);
	ret = gso(false);
	return ret;
}




int ethtool::gro(bool b){

	int ret = 0;
	if(b){
		ret = system(("ethtool -K " + gNetcardName + " gro on").c_str());
	}else{
		ret = system(("ethtool -K " + gNetcardName + " gro off").c_str());
	}
	return ret;
}


int ethtool::lro(bool b){
	int ret = 0;
	if(b){
		ret = system(("ethtool -K " + gNetcardName + " lro on").c_str());
	}else{
		ret = system(("ethtool -K " + gNetcardName + " lro off").c_str());
	}
	return ret;
}


int ethtool::tso(bool b){

	int ret = 0;
	if(b){
		ret = system(("ethtool -K " + gNetcardName + " tso on").c_str());
	}else{
		ret = system(("ethtool -K " + gNetcardName + " tso off").c_str());
	}
	return ret;
}


int ethtool::ufo(bool b){
	int ret = 0;
	if(b){
		ret = system(("ethtool -K " + gNetcardName + " ufo on").c_str());
	}else{
		ret = system(("ethtool -K " + gNetcardName + " ufo off").c_str());
	}
	return ret;
}

int ethtool::gso(bool b){
	int ret = 0;
	if(b){
		ret = system(("ethtool -K " + gNetcardName + " gso on").c_str());
	}else{
		ret = system(("ethtool -K " + gNetcardName + " gso off").c_str());
	}
	return ret;
}
