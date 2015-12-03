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

struct accept_param {
		int server_fd;
		int port;
		struct cnode* config;
		int works_count;
		struct work_param** works;
		struct logsess* logsess;
		struct cert* cert;
};

struct conn {
		int fd;
		struct sockaddr addr;
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
		int fwc;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
