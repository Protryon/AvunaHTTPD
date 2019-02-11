/*
 * mime.h
 *
 *  Created on: Nov 24, 2015
 *      Author: root
 */

#ifndef MIME_H_
#define MIME_H_

#include <unistd.h>

struct mime {
		char* type;
		size_t ext_count;
		char** exts;
};

int loadMimes(const char* file);

char* getMimeForExt(char* ext);

#endif /* MIME_H_ */
