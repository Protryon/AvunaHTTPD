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
#include <fcntl.h>
#include <sys/ioctl.h>
#include "http.h"

void closeConn(struct collection* coll, struct conn* conn) {
	close(conn->fd);
	if (rem_collection(coll, conn)) {
		printf("Failed to delete connection properly! This is bad!\n");
	}
	if (conn->readBuffer != NULL) xfree(conn->readBuffer);
	if (conn->writeBuffer != NULL) xfree(conn->writeBuffer);
	xfree(conn);
}

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
			struct conn* conn = param->conns->data[i];
			if (conn != NULL) {
				conns[fdi] = conn;
				fds[fdi].fd = conn->fd;
				fds[fdi].events = POLLIN | (conn->writeBuffer_size > 0 ? POLLOUT : 0);
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
			if (re == 0) continue;
			if ((re & POLLIN) == POLLIN) {
				int tr = 0;
				ioctl(fds[i].fd, FIONREAD, &tr);
				unsigned char* loc;
				if (conns[i]->readBuffer == NULL) {
					conns[i]->readBuffer = xmalloc(tr); // TODO: max upload?
					conns[i]->readBuffer_size = tr;
					loc = conns[i]->readBuffer;
				} else {
					conns[i]->readBuffer_size += tr;
					conns[i]->readBuffer = xrealloc(conns[i]->readBuffer, conns[i]->readBuffer_size);
					loc = conns[i]->readBuffer + conns[i]->readBuffer_size - tr;
				}
				int r = 0;
				while (r < tr) {
					int x = read(fds[i].fd, loc + r, tr - r);
					if (x <= 0) {
						closeConn(param->conns, conns[i]);
						conns[i] = NULL;
						goto cont;
					}
					r += x;
				}
				static unsigned char tm[4] = { 0x0D, 0x0A, 0x0D, 0x0A };
				int ml = 0;
				for (int x = conns[i]->readBuffer_checked; x < conns[i]->readBuffer_size; x++) {
					if (conns[i]->readBuffer[x] == tm[ml]) {
						ml++;
						if (ml == 4) {
							unsigned char* reqd = xmalloc(x + 2);
							memcpy(reqd, conns[i]->readBuffer, x + 1);
							reqd[x + 1] = 0;
							conns[i]->readBuffer_size -= x + 1;
							conns[i]->readBuffer_checked = 0;
							memmove(conns[i]->readBuffer, conns[i]->readBuffer + x + 1, conns[i]->readBuffer_size);
							struct request* req = xmalloc(sizeof(struct request));
							if (parseRequest(req, (char*) reqd) < 0) {
								printf("Malformed Request!\n");
								xfree(req);
								xfree(reqd);
								closeConn(param->conns, conns[i]);
								goto cont;
							}
							struct response* resp = xmalloc(sizeof(struct response));
							generateResponse(conns[i], resp, req);
							size_t rl = 0;
							unsigned char* rda = serializeResponse(resp, &rl);
							size_t mtr = write(fds[i].fd, rda, rl);
							if (mtr < 0 && errno != EAGAIN) {
								closeConn(param->conns, conns[i]);
								conns[i] = NULL;
							} else if (mtr >= rl) {
								//done writing!
							} else {
								unsigned char* stw = rda + mtr;
								rl -= mtr;
								if (conns[i]->writeBuffer == NULL) {
									conns[i]->writeBuffer = xmalloc(rl); // TODO: max upload?
									conns[i]->writeBuffer_size = rl;
									loc = conns[i]->writeBuffer;
								} else {
									conns[i]->writeBuffer_size += rl;
									conns[i]->writeBuffer = xrealloc(conns[i]->writeBuffer, conns[i]->writeBuffer_size);
									loc = conns[i]->writeBuffer + conns[i]->writeBuffer_size - rl;
								}
								memcpy(loc, stw, rl);
							}
							xfree(rda);
							xfree(req->path);
							xfree(req->version);
							freeHeaders(&req->headers);
							xfree(req);
							freeHeaders(&resp->headers);
							xfree(resp);
							//TODO: free bodies
						}
					} else ml = 0;
				}
				if (conns[i] != NULL) {
					conns[i]->readBuffer_checked = conns[i]->readBuffer_size - 10;
					if (conns[i]->readBuffer_checked < 0) conns[i]->readBuffer_checked = 0;
				}
			}
			if ((re & POLLOUT) == POLLOUT && conns[i] != NULL) {
				size_t mtr = write(fds[i].fd, conns[i]->writeBuffer, conns[i]->writeBuffer_size);
				if (mtr < 0) {
					closeConn(param->conns, conns[i]);
					conns[i] = NULL;
					goto cont;
				} else if (mtr < conns[i]->writeBuffer_size) {
					memmove(conns[i]->writeBuffer, conns[i]->writeBuffer + mtr, conns[i]->writeBuffer_size - mtr);
					conns[i]->writeBuffer_size -= mtr;
					conns[i]->writeBuffer = xrealloc(conns[i]->writeBuffer, conns[i]->writeBuffer_size);
				} else {
					conns[i]->writeBuffer_size = 0;
					xfree(conns[i]->writeBuffer);
					conns[i]->writeBuffer = NULL;
				}
			}
			if ((re & POLLERR) == POLLERR) { //TODO: probably a HUP
				//printf("POLLERR in worker poll! This is bad!\n");
			}
			if ((re & POLLHUP) == POLLHUP && conns[i] != NULL) {
				closeConn(param->conns, conns[i]);
				conns[i] = NULL;
			}
			if ((re & POLLNVAL) == POLLNVAL) {
				printf("Invalid FD in worker poll! This is bad!\n");
			}
			cont: if (--cp == 0) break;
		}
	}
	xfree(mbuf);
}
