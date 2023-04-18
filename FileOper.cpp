/*
 * FileOper.cpp
 *
 *  Created on: Sep 6, 2018
 *      Author: root
 */


#include "FileOper.h"
#include <stdio.h>
#include <string.h>


int FileOper::devfReader(string filename, char ** lpbuf,int *bufsize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("devfReader fopen:%s error\r\n",filename.c_str());
		return -1;
	}

	int buflimit = 0x10000;

	*lpbuf = new char[buflimit];

	char * offset = *lpbuf;
	int offsize = buflimit;

	char *result = 0;
	do{
		result = fgets(offset,offsize,fp);
		if(result > 0){
			int resultlen = strlen(result);
			offset += resultlen;
			offsize -= resultlen;
		}
	}while(result > 0);

	fclose(fp);

	*bufsize = buflimit - offsize;
	*(*lpbuf + *bufsize) = 0;
	return *bufsize;
}



int FileOper::fileReader(string filename, char ** lpbuf,int *bufsize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen:%s error\r\n",filename.c_str());
		return -1;
	}

	ret = fseek(fp, 0, SEEK_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, SEEK_SET);

	*bufsize = filesize ;

	*lpbuf = new char[filesize + 1024];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret == 0)
	{
		return -1;
	}

	*(*lpbuf + filesize) = 0;
	return filesize;
}




int FileOper::fileWriter(string filename, const char * lpdata, int datasize) {
	int ret = 0;

	FILE * fp = fopen( filename.c_str(), "ab+");
	if (fp <= 0)
	{
		printf("fileWriter fopen:%s error\r\n",filename.c_str());
		return -1;
	}

	ret = fwrite(lpdata, 1, datasize, fp);
	fclose(fp);
	if (ret == 0)
	{
		return -1;
	}

	return datasize;
}
