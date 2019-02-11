/*
 * fcgi.h
 *
 *  Created on: Nov 26, 2015
 *      Author: root
 */

#ifndef FCGI_H_
#define FCGI_H_

#include <stdlib.h>
#include <stdint.h>

#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_ABORT_REQUEST 2
#define FCGI_END_REQUEST 3
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_DATA 8
#define FCGI_GET_VALUES 9
#define FCGI_GET_VALUES_RESULT 10
#define FCGI_UNKNOWN_TYPE 11

struct fcgiframe {
		unsigned char type;
		int reqID;
		uint16_t len;
		void* data;
};

int writeFCGIFrame(int fd, struct fcgiframe* fcgif);

int writeFCGIParam(int fd, int reqid, const char* name, const char* value);

int readFCGIFrame(int fd, struct fcgiframe* fcgif);

#endif /* FCGI_H_ */
