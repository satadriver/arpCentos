/*
 * Log.h
 *
 *  Created on: Sep 10, 2018
 *      Author: root
 */

#ifndef LOG_H_
#define LOG_H_


#include <iostream>
using namespace std;


class Log{
public:
	static void log(string str);
	static void logout(string str);
	static void logFile(string str);
};



#endif /* LOG_H_ */
