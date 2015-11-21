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

struct accept_param {
		int server_fd;
		int port;
		struct cnode* config;
		int works_count;
		struct work_param** works;
};

struct conn {
		int fd;
		struct sockaddr addr;
		socklen_t addrlen;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
