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
#include <sys/mman.h>
#include <gnutls/gnutls.h>
#include <nettle/md5.h>
#include "vhost.h"
#include "oqueue.h"
#include "http2.h"

void freeReqsess(struct reqsess rs);

void closeConn(struct work_param* param, struct conn* conn) {
	if (conn->tls) {
		if (conn->handshaked) {
			gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
		}
		gnutls_deinit(conn->session);
	}
	if (conn->fw_tls) {
		if (conn->fw_handshaked) {
			gnutls_bye(conn->fw_session, GNUTLS_SHUT_RDWR);
		}
		gnutls_deinit(conn->fw_session);
	}
	close(conn->fd);
	if (conn->fw_fd >= 0) close(conn->fw_fd);
	if (conn->stream_type >= 0) {
		if (conn->fw_fd != conn->stream_fd) close(conn->stream_fd);
		struct reqsess rs;
		for (int i = 0; i < conn->fwqueue->size; i++) {
			pop_queue(conn->fwqueue, &rs);
			freeReqsess(rs);
		}
	}
	if (conn->fwqueue != NULL) del_queue(conn->fwqueue);
	if (rem_collection(param->conns, conn)) {
		errlog(param->logsess, "Failed to delete connection properly! This is bad!");
	}
	if (conn->readBuffer != NULL) xfree(conn->readBuffer);
	if (conn->fw_readBuffer != NULL) xfree(conn->fw_readBuffer);
	if (conn->writeBuffer != NULL) xfree(conn->writeBuffer);
	xfree(conn);
}

void sendReqsess(struct reqsess rs, int wfd, struct timespec* stt) {
	struct conn* conn = rs.sender;
	struct work_param* param = rs.wp;
	struct response* resp = rs.response;
	struct request* req = rs.request;
	if (!conn->fwed) {
		size_t rl = 0;
		unsigned char* rda = serializeResponse(rs, &rl);
		struct timespec stt2;
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt2);
		double msp = (stt2.tv_nsec / 1000000.0 + stt2.tv_sec * 1000.0) - (stt->tv_nsec / 1000000.0 + stt->tv_sec * 1000.0);
		const char* mip = NULL;
		char tip[48];
		if (conn->addr.sin6_family == AF_INET) {
			struct sockaddr_in *sip4 = (struct sockaddr_in*) &conn->addr;
			mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
		} else if (conn->addr.sin6_family == AF_INET6) {
			struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &conn->addr;
			if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
				mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
			} else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
		} else if (conn->addr.sin6_family == AF_LOCAL) {
			mip = "UNIX";
		} else {
			mip = "UNKNOWN";
		}
		if (mip == NULL) {
			errlog(param->logsess, "Invalid IP Address: %s", strerror(errno));
		}
		acclog(param->logsess, "%s %s %s returned %s took: %f ms", mip, getMethod(req->method), req->path, resp->code, msp);
		ssize_t mtr = conn->tls ? gnutls_record_send(conn->session, rda, rl) : write(wfd, rda, rl);
		if (mtr < 0 && (conn->tls ? gnutls_error_is_fatal(mtr) : errno != EAGAIN)) {
			closeConn(param, conn);
			conn = NULL;
		} else if (mtr >= rl) {
			//done writing!
		} else {
			unsigned char* stw = rda + mtr;
			rl -= mtr;
			unsigned char* loc = NULL;
			if (conn->writeBuffer == NULL) {
				conn->writeBuffer = xmalloc(rl); // TODO: max upload?
				conn->writeBuffer_size = rl;
				loc = conn->writeBuffer;
			} else {
				conn->writeBuffer_size += rl;
				conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size);
				loc = conn->writeBuffer + conn->writeBuffer_size - rl;
			}
			memcpy(loc, stw, rl);
		}
		xfree(rda);
	} else {
		conn->fwed = 0;
	}
}

void freeReqsess(struct reqsess rs) {
	struct response* resp = rs.response;
	struct request* req = rs.request;
	if (!req->atc) xfree(req->path);
	xfree(req->version);
	freeHeaders(req->headers);
	if (req->body != NULL) {
		if (req->body->freeMime) xfree(req->body->mime_type);
		xfree(req->body->data);
		xfree(req->body);
	}
	if (!req->atc) {
		if (resp->body != NULL) {
			if (resp->body->freeMime) xfree(resp->body->mime_type);
			xfree(resp->body->data);
			xfree(resp->body);
		}
		freeHeaders(resp->headers);
	}
	if (!req->atc && resp->parsed == 1) {
		xfree(resp->version);
		xfree(resp->code);
	} else if (!req->atc && resp->parsed) {
		xfree(resp->code);
	}
	xfree(req);
	xfree(resp);
}

void handleRequest(int wfd, struct timespec* stt, struct conn* conn, struct work_param* param, struct request* req) {
	struct response* resp = xmalloc(sizeof(struct response));
	resp->body = NULL;
	resp->parsed = 0;
	resp->code = "500 Internal Server Error";
	resp->version = "HTTP/1.1";
	resp->fromCache = NULL;
	resp->headers = xmalloc(sizeof(struct headers));
	struct reqsess rs;
	rs.wp = param;
	rs.sender = conn;
	rs.response = resp;
	rs.request = req;
	generateResponse(rs);
	int fwed = conn->fwed;
	sendReqsess(rs, wfd, stt);
	if (!fwed) freeReqsess(rs);
}

struct uconn {
		int type;
		struct conn* conn;
};

int handleRead(struct conn* conn, int ct, struct work_param* param, int fd) {
	reqp: if (ct == 0 && conn->reqPosting != NULL && conn->postLeft > 0) {
		if (conn->readBuffer_size >= conn->postLeft) {
			struct timespec stt;
			clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);
			memcpy(conn->reqPosting->body->data + conn->reqPosting->body->len - conn->postLeft, conn->readBuffer, conn->postLeft);
			size_t os = conn->readBuffer_size;
			conn->readBuffer_size -= conn->postLeft;
			conn->readBuffer_checked = 0;
			memmove(conn->readBuffer, conn->readBuffer + conn->postLeft, conn->readBuffer_size);
			conn->postLeft -= os;
			if (conn->postLeft == 0) {
				handleRequest(fd, &stt, conn, param, conn->reqPosting);
				conn->reqPosting = NULL;
			}
		} else goto pc;
	}
	static unsigned char tm[4] = { 0x0D, 0x0A, 0x0D, 0x0A };
	int ml = 0;
	unsigned char* readBuffer = (ct == 0 ? conn->readBuffer : (ct == 1 ? conn->fw_readBuffer : 0));
	sin: ;
	if (ct == 1 && conn->stream_type >= 0) { //todo ct==2
		int se = 0;
		if (conn->stream_type == 0) {
			size_t rbs = conn->fw_readBuffer_size;
			if (conn->frs.response->fromCache != NULL) {
				if (conn->stream_md5 == NULL) {
					conn->stream_md5 = xmalloc(sizeof(struct md5_ctx));
					md5_init(conn->stream_md5);
				}
				md5_update(conn->stream_md5, rbs, readBuffer);
			}
			if (conn->writeBuffer == NULL) {
				conn->writeBuffer = xmalloc(rbs);
			} else {
				conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size + rbs);
			}
			if (conn->frs.request->atc) {
				if (conn->staticStreamCacheBuffer == NULL) {
					conn->staticStreamCacheBuffer = xmalloc(rbs);
					conn->sscbl = 0;
				} else {
					conn->staticStreamCacheBuffer = xrealloc(conn->staticStreamCacheBuffer, conn->sscbl + rbs);
				}
				memcpy(conn->staticStreamCacheBuffer + conn->sscbl, readBuffer, rbs);
				conn->sscbl += rbs;
			}
			memcpy(conn->writeBuffer + conn->writeBuffer_size, readBuffer, rbs);
			conn->writeBuffer_size += rbs;
			size_t ns = conn->fw_readBuffer_size - rbs;
			if (ns > 0) {
				memmove(conn->fw_readBuffer, conn->fw_readBuffer + rbs, conn->fw_readBuffer_size - rbs);
				conn->fw_readBuffer = xrealloc(conn->fw_readBuffer, conn->fw_readBuffer_size - rbs);
			} else {
				xfree(conn->fw_readBuffer);
				conn->fw_readBuffer = NULL;
			}
			conn->fw_readBuffer_size -= rbs;
			conn->streamed += rbs;
			conn->fw_readBuffer_checked = 0;
			if (conn->streamed >= conn->stream_len) {
				if (conn->frs.request->atc) {
					int patc = 0;
					int ib = 0;
					const char* ct = header_get(conn->frs.response->headers, "Content-Type");
					for (int i = 0; i < conn->frs.request->vhost->sub.rproxy.dmime_count; i++) {
						if (streq_nocase(conn->frs.request->vhost->sub.rproxy.dmimes[i], ct)) {
							ib = 1;
							break;
						}
					}
					if (!ib) {
						conn->frs.request->atc = 1;
						struct scache* sc = xmalloc(sizeof(struct scache));
						if (conn->frs.response->body == NULL) {
							conn->frs.response->body = xmalloc(sizeof(struct body));
						}
						conn->frs.response->body->data = conn->staticStreamCacheBuffer;
						conn->staticStreamCacheBuffer = NULL;
						conn->frs.response->body->len = conn->sscbl;
						conn->frs.response->body->stream_type = -1;
						conn->frs.response->body->stream_fd = -1;
						conn->frs.response->body->mime_type = ct;
						conn->frs.response->body->freeMime = 0;
						sc->body = conn->frs.response->body;
						sc->ce = header_get(conn->frs.response->headers, "Content-Encoding") != NULL;
						sc->code = conn->frs.response->code;
						sc->headers = conn->frs.response->headers;
						sc->rp = conn->frs.request->path;
						if (conn->frs.response->body == NULL) {
							sc->etag[0] = '\"';
							memset(sc->etag + 1, '0', 32);
							sc->etag[33] = '\"';
							sc->etag[34] = 0;
						} else {
							struct md5_ctx md5ctx;
							md5_init(&md5ctx);
							md5_update(&md5ctx, conn->frs.response->body->len, conn->frs.response->body->data);
							unsigned char rawmd5[16];
							md5_digest(&md5ctx, 16, rawmd5);
							sc->etag[34] = 0;
							sc->etag[0] = '\"';
							for (int i = 0; i < 16; i++) {
								snprintf(sc->etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
							}
							sc->etag[33] = '\"';
						}
						header_setoradd(conn->frs.response->headers, "ETag", sc->etag);
						addSCache(&conn->frs.request->vhost->sub.rproxy.cache, sc);
						patc = 1;
						conn->frs.response->fromCache = sc;
					} else {
						conn->frs.request->atc = 0;
					}
					if (!ib && !patc) {
						struct body* body = xmalloc(sizeof(struct body));
						conn->frs.response->fromCache->body = body;
						body->data = conn->staticStreamCacheBuffer;
						conn->staticStreamCacheBuffer = NULL;
						body->len = conn->sscbl;
						body->stream_type = -1;
						body->stream_fd = -1;
						body->mime_type = ct;
						body->freeMime = 0;
					}
				}
				if (conn->stream_md5 != NULL) {
					unsigned char rawmd5[16];
					md5_digest(conn->stream_md5, 16, rawmd5);
					xfree(conn->stream_md5);
					conn->stream_md5 = NULL;
					for (int i = 0; i < 16; i++) {
						snprintf(conn->frs.response->fromCache->etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
					}
					header_setoradd(conn->frs.response->fromCache->headers, "ETag", conn->frs.response->fromCache->etag);
				}
				conn->stream_type = -1;
				conn->streamed = 0;
				freeReqsess(conn->frs);
				pop_queue(conn->fwqueue, NULL);
				se = 1;
			}
		} else if (conn->stream_type == 1) { // chunked already

		}
		if (!se) goto pc;
	}
	for (size_t x = (ct == 0 ? conn->readBuffer_checked : (ct == 1 ? conn->fw_readBuffer_checked : 0)); x < (ct == 0 ? conn->readBuffer_size : (ct == 1 ? conn->fw_readBuffer_size : 0)); x++) {
		if (readBuffer[x] == tm[ml]) {
			ml++;
			if (ml == 4) {
				unsigned char* reqd = xmalloc(x + 2);
				memcpy(reqd, readBuffer, x + 1);
				reqd[x + 1] = 0;
				if (ct == 0) {
					conn->readBuffer_size -= x + 1;
					conn->readBuffer_checked = 0;
				} else if (ct == 1) {
					conn->fw_readBuffer_size -= x + 1;
					conn->fw_readBuffer_checked = 0;
				}
				memmove(readBuffer, readBuffer + x + 1, ct == 0 ? conn->readBuffer_size : (ct == 1 ? conn->fw_readBuffer_size : 0));
				struct timespec stt;
				clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);

				if (ct == 0) {
					struct request* req = xmalloc(sizeof(struct request));
					if (parseRequest(req, (char*) reqd, param->maxPost) < 0) {
						errlog(param->logsess, "Malformed Request!");
						xfree(req);
						xfree(reqd);
						closeConn(param, conn);
						return 1;
					}
					if (req->body != NULL) {
						conn->reqPosting = req;
						conn->postLeft = req->body->len;
						goto reqp;
					}
					handleRequest(fd, &stt, conn, param, req);
				} else if (ct == 1) {
					struct reqsess rs;
					peek_queue(conn->fwqueue, &rs);
					if (parseResponse(rs, (char*) reqd) < 0) {
						errlog(param->logsess, "Malformed Response!");
						xfree(rs.response);
						xfree(reqd);
						closeConn(param, conn);
						return 1;
					}
					if (rs.response->body != NULL) {
						rs.response->body->mime_type = header_get(rs.response->headers, "Content-Type");
						rs.response->body->freeMime = 0;
					}
					sendReqsess(rs, rs.sender->fd, &stt);
					if (rs.response->body != NULL && rs.response->body->stream_type >= 0) {
						conn->stream_fd = rs.response->body->stream_fd;
						conn->stream_type = rs.response->body->stream_type;
						conn->stream_len = rs.response->body->len;
						conn->frs = rs;
						goto sin;
					} else {
						conn->stream_type = -1;
						pop_queue(conn->fwqueue, NULL);
						freeReqsess(rs);
					}
				}
			}
		} else ml = 0;
	}
	pc: if (conn != NULL) {
		if (conn->readBuffer_size >= 10) conn->readBuffer_checked = conn->readBuffer_size - 10;
		else conn->readBuffer_checked = 0;
	}
	return 0;
}

int finalizeHeaders2(struct conn* conn, struct work_param* param) {

	return 0;
}

int writeFrame(struct conn* conn, struct frame* frame, struct work_param* param) {
	unsigned char head[9];
	memcpy(head, &frame->length + sizeof(size_t) - 3, 3);
	head[3] = frame->type;
	head[4] = frame->flags;
	memcpy(head + 5, &frame->stream, sizeof(uint32_t));
	if (conn->writeBuffer == NULL) {
		conn->writeBuffer = xmalloc(frame->length + 9);
		conn->writeBuffer_size = 0;
	} else {
		conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size + frame->length + 9);
	}
	memcpy(conn->writeBuffer + conn->writeBuffer_size, head, 9);
	memcpy(conn->writeBuffer + conn->writeBuffer_size + 9, frame->uf, frame->length);
	return 0;
}

void freeFrame(struct frame* frame) {
	xfree(frame->uf);
}

int handleRead2(struct conn* conn, int ct, struct work_param* param, int fd) {
	if (conn->readBuffer_size >= 9) {
		size_t len = 0;
		memcpy(&len + sizeof(len) - 3, conn->readBuffer, 3);
		if (conn->readBuffer_size >= 9 + len) {
			struct frame* frame = xmalloc(sizeof(struct frame));
			frame->length = len;
			frame->type = conn->readBuffer[3];
			frame->flags = conn->readBuffer[4];
			frame->stream = 0;
			frame->strobj = NULL;
			memcpy(&frame->stream + sizeof(size_t) - 4, conn->readBuffer + 5, 4);
			if (frame->stream > 0) for (int i = 0; i < conn->http2_stream_size; i++) {
				if (conn->http2_stream[i]->id == frame->stream) {
					frame->strobj = conn->http2_stream[i];
					break;
				}
			}
			printf("%i\n", frame->type);
			unsigned char* lframe = conn->readBuffer + 9;
			if (frame->type == FRAME_DATA_ID) {
				if (frame->strobj == NULL) {
					errno = EINVAL;
					return -1;
				}
				unsigned char pad = 0;
				size_t dl = len;
				if (frame->flags & 0x8 == 0x8) {
					if (len < 1) {
						errno = EINVAL;
						return -1;
					}
					pad = lframe[0];
					if (len < pad + 1) {
						errno = EINVAL;
						return -1;
					}
					lframe++;
					len -= 1 + pad;
				}
				if (frame->strobj->http2_dataBuffer == NULL) {
					frame->strobj->http2_dataBuffer = xmalloc(len);
					frame->strobj->http2_dataBuffer_size = 0;
				} else {
					frame->strobj->http2_dataBuffer = xrealloc(frame->strobj->http2_dataBuffer, frame->strobj->http2_dataBuffer_size + len);
				}
				memcpy(frame->strobj->http2_dataBuffer, frame->strobj->http2_dataBuffer_size + lframe, len);
				frame->strobj->http2_dataBuffer_size += len;
			} else if (frame->type == FRAME_HEADERS_ID) {
				if (frame->strobj == NULL) {
					frame->strobj = xmalloc(sizeof(struct http2_stream)); //TODO reuse mem space in conn->http2_stream
					frame->strobj->id = frame->stream;
					frame->strobj->http2_dataBuffer = NULL;
					frame->strobj->http2_headerBuffer = NULL;
					frame->strobj->http2_dataBuffer_size = 0;
					frame->strobj->http2_headerBuffer_size = 0;
					if (conn->http2_stream == NULL) {
						conn->http2_stream = xmalloc(sizeof(struct http2_stream*));
						conn->http2_stream_size = 0;
					} else {
						conn->http2_stream = xrealloc(conn->http2_stream, sizeof(struct http2_stream*) * (conn->http2_stream_size + 1));
					}
					conn->http2_stream[conn->http2_stream_size] = frame->strobj;
					conn->http2_stream_size++;
				}
				unsigned char pad = 0;
				size_t dl = len;
				if (frame->flags & 0x8 == 0x8) {
					if (len < 1) {
						errno = EINVAL;
						return -1;
					}
					pad = lframe[0];
					if (len < pad + 1) {
						errno = EINVAL;
						return -1;
					}
					lframe++;
					len -= 1 + pad;
				}
				if (frame->flags & 0x20 == 0x20) {
					if (len < 5) {
						errno = EINVAL;
						return -1;
					}
					len -= 5; //TODO: stream dependency
				}
				if (frame->strobj->http2_headerBuffer == NULL) {
					frame->strobj->http2_headerBuffer = xmalloc(len);
					frame->strobj->http2_headerBuffer_size = 0;
				} else {
					frame->strobj->http2_headerBuffer = xrealloc(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + len);
				}
				memcpy(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + lframe, len);
				frame->strobj->http2_headerBuffer_size += len;
				if (frame->flags & 0x4 == 0x4) {
					if (finalizeHeaders2(conn, param) == -1) return -1;
				}
			} else if (frame->type == FRAME_PRIORITY_ID) {
				//TODO: impl
			} else if (frame->type == FRAME_RST_STREAM_ID) {
				//TODO: impl
			} else if (frame->type == FRAME_SETTINGS_ID) {
				if (len % 6 == 0) {
					for (int i = 0; i < len / 6; i++) {
						int id = 0;
						memcpy(&id + sizeof(int) - 2, lframe + len + (i * 6), 2);
						uint32_t val = 0;
						memcpy(&val, lframe + len + (i * 6) + 2, 4);

					}
				}
			} else if (frame->type == FRAME_PUSH_PROMISE_ID) {
				//TODO impl
			} else if (frame->type == FRAME_PING_ID) {

			} else if (frame->type == FRAME_GOAWAY_ID) {
				closeConn(param, conn);
				errno = ECONNRESET;
				return -1;
			} else if (frame->type == FRAME_WINDOW_UPDATE_ID) {

			} else if (frame->type == FRAME_CONTINUATION_ID) {
				if (frame->strobj == NULL) {
					closeConn(param, conn);
					errno = ECONNRESET;
					return -1;
				}
				size_t dl = len;
				if (frame->strobj->http2_headerBuffer == NULL) {
					frame->strobj->http2_headerBuffer = xmalloc(len);
					frame->strobj->http2_headerBuffer_size = 0;
				} else {
					frame->strobj->http2_headerBuffer = xrealloc(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + len);
				}
				memcpy(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + lframe, len);
				frame->strobj->http2_headerBuffer_size += len;
				if (frame->flags & 0x4 == 0x4) {
					if (finalizeHeaders2(conn, param) == -1) return -1;
				}
			}
			if (frame->flags & 0x1 == 0x1) {
				//close stream
			}
			conn->readBuffer_size -= 9 + len;
			memmove(conn->readBuffer, conn->readBuffer + 9 + len, conn->readBuffer_size);
		}
	}
	return 0;
}

void run_work(struct work_param* param) {
	if (pipe(param->pipes) != 0) {
		errlog(param->logsess, "Failed to create pipe! %s", strerror(errno));
		return;
	}
	unsigned char wb;
	unsigned char* mbuf = xmalloc(1024);
	while (1) {
		pthread_rwlock_rdlock(&param->conns->data_mutex);
		size_t cc = param->conns->count;
		size_t mfds = cc + 1;
		struct pollfd* fds = xmalloc(sizeof(struct pollfd) * mfds);
		struct uconn* conns = xmalloc(sizeof(struct uconn) * (mfds - 1));
		size_t fdi = 0;
		size_t fdxi = 0;
		for (int i = 0; i < param->conns->size; i++) {
			struct conn* conn = param->conns->data[i];
			if (conn != NULL) {
				if (conn->fwqueue != NULL) {
					pthread_mutex_lock(&conn->fwqueue->data_mutex);
					if (conn->fwqueue->size > 0) {
						mfds += 1;
						fds = xrealloc(fds, sizeof(struct pollfd) * mfds);
						conns = xrealloc(conns, sizeof(struct uconn) * (mfds - 1));
						conns[fdxi].conn = conn;
						conns[fdxi].type = 1;
						fds[fdxi].fd = conn->fw_fd;
						fds[fdxi].events = POLLIN;
						fds[fdxi++].revents = 0;
					}
					pthread_mutex_unlock(&conn->fwqueue->data_mutex);
				}
				if (conn->stream_type >= 0 && conn->stream_fd != conn->fw_fd) { // TODO: finish impl
					mfds += 1;
					fds = xrealloc(fds, sizeof(struct pollfd) * mfds);
					conns = xrealloc(conns, sizeof(struct uconn) * (mfds - 1));
					conns[fdxi].conn = conn;
					conns[fdxi].type = 2;
					fds[fdxi].fd = conn->stream_fd;
					fds[fdxi].events = POLLIN;
					fds[fdxi++].revents = 0;
				}
				conns[fdxi].conn = conn;
				conns[fdxi].type = 0;
				fds[fdxi].fd = conn->fd;
				fds[fdxi].events = POLLIN | ((conn->writeBuffer_size > 0 || (conn->tls && !conn->handshaked && gnutls_record_get_direction(conn->session))) ? POLLOUT : 0);
				fds[fdxi++].revents = 0;
				fdi++;
				if (fdi == cc) break;
			}
		}
		pthread_rwlock_unlock(&param->conns->data_mutex);
		fds[mfds - 1].fd = param->pipes[0];
		fds[mfds - 1].events = POLLIN;
		fds[mfds - 1].revents = 0;
		int cp = poll(fds, mfds, -1);
		if (cp < 0) {
			errlog(param->logsess, "Poll error in worker thread! %s", strerror(errno));
		} else if (cp == 0) {
			xfree(fds);
			xfree(conns);
			continue;
		} else if ((fds[mfds - 1].revents & POLLIN) == POLLIN) {
			if (read(param->pipes[0], &wb, 1) < 1) errlog(param->logsess, "Error reading from pipe, infinite loop COULD happen here.");
			if (cp-- == 1) {
				xfree(fds);
				xfree(conns);
				continue;
			}
		}
		for (int i = 0; i < mfds - 1; i++) {
			int re = fds[i].revents;
			if (re == 0) continue;
			struct conn* conn = conns[i].conn;
			int ct = conns[i].type;
			if (ct != 0 && ct != 1) {
				errlog(param->logsess, "Invalid connection type! %i", conns[i].type);
				continue;
			}

			if ((re & POLLHUP) == POLLHUP && conn != NULL) {
				closeConn(param, conn);
				conn = NULL;
				goto cont;
			}
			if ((re & POLLERR) == POLLERR) { //TODO: probably a HUP
				//printf("POLLERR in worker poll! This is bad!\n");
				closeConn(param, conn);
				conn = NULL;
				goto cont;
			}
			if ((re & POLLNVAL) == POLLNVAL) {
				errlog(param->logsess, "Invalid FD in worker poll! This is bad!");
				closeConn(param, conn);
				conn = NULL;
				goto cont;
			}
			if (ct == 0 && conn->tls && !conn->handshaked) {
				int r = gnutls_handshake(conn->session);
				if (gnutls_error_is_fatal(r)) {
					closeConn(param, conn);
					goto cont;
				} else if (r == GNUTLS_E_SUCCESS) {
					conn->handshaked = 1;
				}
				goto cont;
			} else if (ct == 1 && conn->fw_tls && !conn->fw_handshaked) {
				int r = gnutls_handshake(conn->fw_session);
				if (gnutls_error_is_fatal(r)) {
					closeConn(param, conn);
					goto cont;
				} else if (r == GNUTLS_E_SUCCESS) {
					conn->fw_handshaked = 1;
				}
				goto cont;
			}
			if ((re & POLLIN) == POLLIN) {
				size_t tr = 0;
				if (ct == 1 ? conn->fw_tls : (ct == 0 ? conn->tls : 0)) {
					if (ct == 0) tr = gnutls_record_check_pending(conn->session);
					else if (ct == 1) tr = gnutls_record_check_pending(conn->fw_session);
					if (tr == 0) {
						tr += 1024;
					}
				} else {
					ioctl(fds[i].fd, FIONREAD, &tr);
				}
				unsigned char* loc;
				if (ct == 0) {
					if (conn->readBuffer == NULL) {
						conn->readBuffer = xmalloc(tr); // TODO: max upload?
						conn->readBuffer_size = tr;
						loc = conn->readBuffer;
					} else {
						conn->readBuffer_size += tr;
						conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
						loc = conn->readBuffer + conn->readBuffer_size - tr;
					}
				} else if (ct == 1) {
					if (conn->fw_readBuffer == NULL) {
						conn->fw_readBuffer = xmalloc(tr); // TODO: max upload?
						conn->fw_readBuffer_size = tr;
						loc = conn->fw_readBuffer;
					} else {
						conn->fw_readBuffer_size += tr;
						conn->fw_readBuffer = xrealloc(conn->fw_readBuffer, conn->fw_readBuffer_size);
						loc = conn->fw_readBuffer + conn->fw_readBuffer_size - tr;
					}
				}
				ssize_t r = 0;
				if (r == 0 && tr == 0) { // nothing to read, but wont block.
					ssize_t x = 0;
					if (conn->tls) {
						if (ct == 0) x = gnutls_record_recv(conn->session, loc + r, tr - r);
						else if (ct == 1) x = gnutls_record_recv(conn->fw_session, loc + r, tr - r);
						if (x <= 0 && gnutls_error_is_fatal(x)) {
							if (ct == 1) {
								errlog(param->logsess, "TLS Error receiving from backend server! %s", gnutls_strerror(x));
							}
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						} else if (x <= 0) {
							if (r < tr) {
								if (ct == 0) {
									conn->readBuffer_size += r - tr;
									conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
								} else if (ct == 1) {
									conn->fw_readBuffer_size += r - tr;
									conn->fw_readBuffer = xrealloc(conn->fw_readBuffer, conn->fw_readBuffer_size);
								}
								tr = r;
							}
							break;
						}
					} else {
						x = read(fds[i].fd, loc + r, tr - r);
						if (x <= 0) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						}
					}
					r += x;
				}
				while (r < tr) {
					ssize_t x = 0;
					if (conn->tls) {
						if (ct == 0) x = gnutls_record_recv(conn->session, loc + r, tr - r);
						else if (ct == 1) x = gnutls_record_recv(conn->fw_session, loc + r, tr - r);
						if (x <= 0 && gnutls_error_is_fatal(x)) {
							if (ct == 1) {
								errlog(param->logsess, "TLS Error receiving from backend server! %s", gnutls_strerror(x));
							}
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						} else if (x <= 0) {
							if (r < tr) {
								if (ct == 0) {
									conn->readBuffer_size += r - tr;
									conn->readBuffer = xrealloc(conn->readBuffer, conn->readBuffer_size);
								} else if (ct == 1) {
									conn->fw_readBuffer_size += r - tr;
									conn->fw_readBuffer = xrealloc(conn->fw_readBuffer, conn->fw_readBuffer_size);
								}
								tr = r;
							}
							break;
						}
					} else {
						x = read(fds[i].fd, loc + r, tr - r);
						if (x <= 0) {
							closeConn(param, conn);
							conn = NULL;
							goto cont;
						}
					}
					r += x;
				}
				int p = 0;
				if (conn->proto == 0) p = handleRead(conn, ct, param, fds[i].fd);
				else if (conn->proto == 1) p = handleRead2(conn, ct, param, fds[i].fd);
				if (p == 1) {
					goto cont;
				}
			}
			if ((re & POLLOUT) == POLLOUT && conn != NULL) {
				ssize_t mtr = conn->tls ? gnutls_record_send(conn->session, conn->writeBuffer, conn->writeBuffer_size) : write(fds[i].fd, conn->writeBuffer, conn->writeBuffer_size);
				if (mtr < 0 && (conn->tls ? gnutls_error_is_fatal(mtr) : errno != EAGAIN)) {
					closeConn(param, conn);
					conn = NULL;
					goto cont;
				} else if (mtr < 0) {
					goto cont;
				} else if (mtr < conn->writeBuffer_size) {
					memmove(conn->writeBuffer, conn->writeBuffer + mtr, conn->writeBuffer_size - mtr);
					conn->writeBuffer_size -= mtr;
					conn->writeBuffer = xrealloc(conn->writeBuffer, conn->writeBuffer_size);
				} else {
					conn->writeBuffer_size = 0;
					xfree(conn->writeBuffer);
					conn->writeBuffer = NULL;
				}
			}
			cont: if (--cp == 0) break;
		}
		xfree(conns);
		xfree(fds);
	}
	xfree(mbuf);
}
