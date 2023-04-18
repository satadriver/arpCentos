/*
 * LocalParam.h
 *
 *  Created on: Sep 6, 2018
 *      Author: root
 */
#pragma once
#ifndef LOCALPARAM_H_
#define LOCALPARAM_H_



class NetParam{
public:
	static int getLocalNetParams();
	static int getGatewayFromArp();

	static int makemtu();
};



#endif /* LOCALPARAM_H_ */
