/*
 * work.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#include "work.h"
#include "accept.h"
#include "xstring.h"
#include <errno.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include "collection.h"
#include "util.h"
#include "streams.h"

void run_work(struct work_param* param) {
	if (pipe(param->pipes) != 0) {
		printf("Failed to create pipe! %s\n", strerror(errno));
		return;
	}
	unsigned char wb;
	unsigned char* mbuf = xmalloc(1024);
	while (1) {
		pthread_mutex_lock(&param->conns->data_mutex);
		size_t cc = param->conns->count;
		struct pollfd fds[cc + 1];
		struct conn* conns[cc];
		int fdi = 0;
		for (int i = 0; i < param->conns->size; i++) {
			if (param->conns->data[i * param->conns->dsize] != NULL) {
				conns[fdi] = (param->conns->data[i * param->conns->dsize]);
				fds[fdi].fd = conns[fdi]->fd;
				fds[fdi].events = POLLIN;
				fds[fdi++].revents = 0;
				if (fdi == cc) break;
			}
		}
		pthread_mutex_unlock(&param->conns->data_mutex);
		fds[cc].fd = param->pipes[0];
		fds[cc].events = POLLIN;
		fds[cc].revents = 0;
		int cp = poll(fds, cc + 1, -1);
		if (cp < 0) {
			printf("Poll error in worker thread! %s\n", strerror(errno));
		} else if (cp == 0) continue;
		else if ((fds[cc].revents & POLLIN) == POLLIN) {
			if (read(param->pipes[0], &wb, 1) < 1) printf("Error reading from pipe, infinite loop COULD happen here.\n");
			if (cp-- == 1) continue;
		}
		for (int i = 0; i < cc; i++) {
			int re = fds[i].revents;
			if ((re & POLLIN) == POLLIN) {
				while (readLine(fds[i].fd, (char*) mbuf, 1024) < ((size_t) - 1)) {
					printf("%s\n", mbuf);
					writeLine(fds[i].fd, (char*) mbuf, strlen((char*) mbuf));
				}
			}
			if ((re & POLLERR) == POLLERR) {
				printf("POLLERR in worker poll! This is bad!\n");
			}
			if ((re & POLLHUP) == POLLHUP) {
				rem_collection(param->conns, &conns[i]);
				xfree(&conns[i]);
			}
			if ((re & POLLNVAL) == POLLNVAL) {
				printf("Invalid FD in worker poll! This is bad!\n");
			}
			if (--cp == 0) break;
		}
	}
}
