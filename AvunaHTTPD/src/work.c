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
#include "log.h"
#include "time.h"
#include <arpa/inet.h>

void closeConn(struct work_param* param, struct conn* conn) {
	close(conn->fd);
	if (rem_collection(param->conns, conn)) {
		errlog(param->logsess, "Failed to delete connection properly! This is bad!");
	}
	if (conn->readBuffer != NULL) xfree(conn->readBuffer);
	if (conn->writeBuffer != NULL) xfree(conn->writeBuffer);
	xfree(conn);
}

void run_work(struct work_param* param) {
	if (pipe(param->pipes) != 0) {
		errlog(param->logsess, "Failed to create pipe! %s", strerror(errno));
		return;
	}
	unsigned char wb;
	unsigned char* mbuf = xmalloc(1024);
	char tip[48];
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
			errlog(param->logsess, "Poll error in worker thread! %s", strerror(errno));
		} else if (cp == 0) continue;
		else if ((fds[cc].revents & POLLIN) == POLLIN) {
			if (read(param->pipes[0], &wb, 1) < 1) errlog(param->logsess, "Error reading from pipe, infinite loop COULD happen here.");
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
						closeConn(param, conns[i]);
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
							struct timespec stt;
							clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);
							struct request* req = xmalloc(sizeof(struct request));
							if (parseRequest(req, (char*) reqd) < 0) {
								errlog(param->logsess, "Malformed Request!");
								xfree(req);
								xfree(reqd);
								closeConn(param, conns[i]);
								goto cont;
							}
							struct response* resp = xmalloc(sizeof(struct response));
							struct reqsess rs;
							rs.wp = param;
							rs.sender = conns[i];
							rs.response = resp;
							rs.request = req;
							generateResponse(rs);
							size_t rl = 0;
							unsigned char* rda = serializeResponse(resp, &rl);
							struct timespec stt2;
							clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt2);
							double msp = (stt2.tv_nsec / 1000000.0 + stt2.tv_sec * 1000.0) - (stt.tv_nsec / 1000000.0 + stt.tv_sec * 1000.0);
							const char* mip = NULL;
							if (conns[i]->addr.sa_family == AF_INET) {
								struct sockaddr_in *sip4 = (struct sockaddr_in*) &conns[i]->addr;
								mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
							} else if (conns[i]->addr.sa_family == AF_INET6) {
								struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conns[i]->addr;
								mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
							} else if (conns[i]->addr.sa_family == AF_LOCAL) {
								mip = "UNIX";
							} else {
								mip = "UNKNOWN";
							}
							if (mip == NULL) {
								errlog(param->logsess, "Invalid IP Address: %s", strerror(errno));
							}
							acclog(param->logsess, "%s %s %s returned %s took: %f ms", mip, getMethod(req->method), req->path, resp->code, msp);
							size_t mtr = write(fds[i].fd, rda, rl);
							if (mtr < 0 && errno != EAGAIN) {
								closeConn(param, conns[i]);
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
							if (req->body != NULL) {
								xfree(req->body->data);
								xfree(req->body);
							}
							xfree(req);
							if (resp->body != NULL) {
								xfree(resp->body->data);
								xfree(resp->body);
							}
							freeHeaders(&resp->headers);
							xfree(resp);
						}
					} else ml = 0;
				}
				if (conns[i] != NULL) {
					if (conns[i]->readBuffer_size >= 10) conns[i]->readBuffer_checked = conns[i]->readBuffer_size - 10;
					else conns[i]->readBuffer_checked = 0;
				}
			}
			if ((re & POLLOUT) == POLLOUT && conns[i] != NULL) {
				size_t mtr = write(fds[i].fd, conns[i]->writeBuffer, conns[i]->writeBuffer_size);
				if (mtr < 0) {
					closeConn(param, conns[i]);
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
				closeConn(param, conns[i]);
				conns[i] = NULL;
			}
			if ((re & POLLNVAL) == POLLNVAL) {
				errlog(param->logsess, "Invalid FD in worker poll! This is bad!");
			}
			cont: if (--cp == 0) break;
		}
	}
	xfree(mbuf);
}
