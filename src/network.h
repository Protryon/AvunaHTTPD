/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include <avuna/server.h>
#include <avuna/connection.h>
#include <avuna/queue.h>
#include <avuna/http.h>
#include <stdlib.h>

struct work_param {
    size_t i;
    struct server_info* server;
    int epoll_fd;
    struct connection_manager* manager;
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
