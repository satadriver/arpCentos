/*
 * config.h
 *
 *  Created on: Nov 12, 2018
 *      Author: root
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#pragma once

#include <string>

#include <vector>
#include "PublicUtils.h"

using namespace std;

class Config {
public:
	static int getAttackTarget(string fn, vector<CLIENTADDRESSES> &targets,unsigned int *fakeip,int*arpdelay);

	static int getAttackTargetFromCmd(char * buf, vector<CLIENTADDRESSES> & targets);

	static int addTarget(unsigned int ip,vector <CLIENTADDRESSES>& list);

	static int addTarget(vector<CLIENTADDRESSES> & targets, unsigned int recverip, unsigned char mac[MAC_ADDRESS_SIZE]);

	static int getSubnetSize() ;
	static unsigned int getProxyIP(vector<CLIENTADDRESSES> targets);
};





#endif /* CONFIG_H_ */
