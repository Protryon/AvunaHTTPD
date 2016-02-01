/*
 * accept.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef ACCEPT_H_
#define ACCEPT_H_

#include "config.h"
#include "collection.h"
#include <sys/socket.h>
#include "work.h"
#include "log.h"
#include "tls.h"
#include <gnutls/gnutls.h>
#include <netinet/ip6.h>
#include "oqueue.h"
#include "http.h"
#include <stdint.h>

struct accept_param {
		int server_fd;
		int port;
		struct cnode* config;
		size_t works_count;
		struct work_param** works;
		struct logsess* logsess;
		struct cert* cert;
};

struct http2_stream {
		uint32_t id;
		unsigned char* http2_dataBuffer;
		size_t http2_dataBuffer_size;
		unsigned char* http2_headerBuffer;
		size_t http2_headerBuffer_size;
};

struct conn {
		int fd;
		struct sockaddr_in6 addr; //may not be ipv6, but we need to allocate the space.
		socklen_t addrlen;
		unsigned char* readBuffer;
		size_t readBuffer_size;
		size_t readBuffer_checked;
		unsigned char* writeBuffer;
		size_t writeBuffer_size;
		size_t postLeft;
		struct request* reqPosting;
		int tls;
		int handshaked;
		gnutls_session_t session;
		int fw_fd;
		int fwed;
		struct queue *fwqueue;
		unsigned char* fw_readBuffer;
		size_t fw_readBuffer_size;
		size_t fw_readBuffer_checked;
		int fw_tls;
		int fw_handshaked;
		gnutls_session_t fw_session;
		int stream_fd;
		int stream_type;
		size_t stream_len;
		size_t streamed;
		struct reqsess frs;
		struct md5_ctx* stream_md5;
		size_t sscbl;
		unsigned char* staticStreamCacheBuffer;
		int proto;
		struct http2_stream** http2_stream;
		size_t http2_stream_size;
		size_t nextStream;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
