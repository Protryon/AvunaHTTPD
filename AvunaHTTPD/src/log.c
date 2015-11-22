/*
 * log.c
 *
 *  Created on: Nov 22, 2015
 *      Author: root
 */
#include "log.h"
#include <stdio.h>
#include <sys/time.h>
#include "xstring.h"
#include <pthread.h>
#include <errno.h>

void accessLog(char* log, struct logsess* logsess) {
	if (logsess->lmutex == NULL) {
		if (pthread_mutex_init(logsess->lmutex, NULL) == -1) {
			printf("Failed to create logging mutex! %s\n", strerror(errno));
			logsess->lmutex = NULL;
		}
	}
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (logsess->lmutex != NULL) pthread_mutex_lock(logsess->lmutex);
	struct tm *ctm = localtime(&tv.tv_sec);
	char ct[32]; // the above uses a static buffer, so problems could ensue, but it would be the same time being overwritten...
	strftime(ct, 31, "%Y-%m-%d %H:%M:%S", ctm);
	if (fprintf(stdout, "[%s] %s\n", ct, log) < 0) {
		//TODO: we can't write to stdout, nothing we can do!
	}
	if (logsess->access_fd != NULL) {
		if (fprintf(logsess->access_fd, "[%s] %s\n", ct, log) < 0) {
			errorLog("Failed writing to accesslog!", logsess);
		}
	}
	if (logsess->lmutex != NULL) pthread_mutex_unlock(logsess->lmutex);
}

void errorLog(char* log, struct logsess* logsess) {
	if (logsess->lmutex == NULL) {
		if (pthread_mutex_init(logsess->lmutex, NULL) == -1) {
			printf("Failed to create logging mutex! %s\n", strerror(errno));
			logsess->lmutex = NULL;
		}
	}
	struct timeval tv;
	gettimeofday(&tv, NULL);
	if (logsess->lmutex != NULL) pthread_mutex_lock(logsess->lmutex);
	struct tm *ctm = localtime(&tv.tv_sec);
	char ct[32]; // the above uses a static buffer, so problems could ensue, but it would be the same time being overwritten...
	strftime(ct, 31, "%Y-%m-%d %H:%M:%S", ctm);
	fprintf(stderr, "[%s] %s\n", ct, log);
	if (logsess->error_fd != NULL) {
		fprintf(logsess->error_fd, "[%s] %s\n", ct, log);
	}
	if (logsess->lmutex != NULL) pthread_mutex_unlock(logsess->lmutex);
}

