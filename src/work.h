/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include <avuna/server.h>
#include <stdlib.h>

#define PROTO_HTTP1 0
#define PROTO_HTTP2 1

struct work_param {
    size_t i;
    struct server_info* server;
    int pipes[2];
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
