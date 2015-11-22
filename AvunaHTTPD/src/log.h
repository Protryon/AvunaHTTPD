/*
 * log.h
 *
 *  Created on: Nov 22, 2015
 *      Author: root
 */

#ifndef LOG_H_
#define LOG_H_

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

struct logsess {
		pthread_mutex_t* lmutex;
		FILE* access_fd;
		FILE* error_fd;
};

void accessLog(char* log, struct logsess* logsess);

void errorLog(char* log, struct logsess* logsess);

#endif /* LOG_H_ */
