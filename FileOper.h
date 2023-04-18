/*
 * FileOper.h
 *
 *  Created on: Sep 6, 2018
 *      Author: root
 */


#pragma once
#ifndef FILEOPER_H_
#define FILEOPER_H_


#include <iostream>

using namespace std;

class FileOper{
public:
	static int fileReader(string filename, char ** lpbuf,int *bufsize) ;
	static int fileWriter(string filename, const char * lpdate, int datesize) ;
	static int devfReader(string filename, char ** lpbuf,int *bufsize);
};



#endif /* FILEOPER_H_ */
