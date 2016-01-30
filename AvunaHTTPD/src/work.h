/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include "collection.h"
#include "accept.h"
#include "log.h"
#include "cache.h"

#define PROTO_HTTP1 0;
#define PROTO_HTTP2 1;

struct work_param {
		int i;
		struct collection* conns;
		int pipes[2];
		struct logsess* logsess;
		size_t vhosts_count;
		struct vhost** vhosts;
		int sport;
		size_t maxPost;
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
