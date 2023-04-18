/*
 * ethtool.h
 *
 *  Created on: Sep 8, 2018
 *      Author: root
 */


#pragma once
#ifndef ETHTOOL_H_
#define ETHTOOL_H_

#include "PublicUtils.h"

class ethtool{
public:
	static int gro(bool b);
	static int lro(bool b);
	static int gso(bool b);
	static int ufo(bool b);
	static int tso(bool b);

	static int closeall();

};


#endif /* ETHTOOL_H_ */
