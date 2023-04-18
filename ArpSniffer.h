/*
 * ArpSniffer.h
 *
 *  Created on: Sep 8, 2018
 *      Author: root
 */


#pragma once
#ifndef ARPSNIFFER_H_
#define ARPSNIFFER_H_

#include "PublicUtils.h"

class ArpSniffer{
public:

	static int getHost();

	static void* getHostNext(void*param);
};


#endif /* ARPSNIFFER_H_ */
