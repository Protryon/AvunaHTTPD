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

#define VHOST_HTDOCS 0
#define VHOST_RPROXY 1
#define VHOST_REDIRECT 2
#define VHOST_PROXY 3

struct errpage {
		char* code;
		char* page;
};

struct vhost_htdocs {
		char* htdocs;
		int symlock;
		int nohardlinks;
		size_t index_count;
		char** index;
		size_t errpage_count;
		struct errpage** errpages;
		size_t cacheType_count;
		char** cacheTypes;
		size_t maxAge;
		int enableGzip;
};

struct vhost_rproxy {
		char* forward;
		struct headers* headers;
		int xfor;
};

struct vhost_redirect {
		char* redir;
};

struct vhost_proxy {
		int xfor;
};

union vhost_sub {
		struct vhost_htdocs htdocs;
		struct vhost_rproxy rproxy;
		struct vhost_redirect redirect;
		struct vhost_proxy proxy;
};

struct vhost {
		int type;
		size_t host_count; // if 0, all hosts match
		char** hosts;
		char* id;
		union vhost_sub sub;
};

struct work_param {
		struct collection* conns;
		int pipes[2];
		struct logsess* logsess;
		size_t vhosts_count;
		struct vhost** vhosts;
};

void run_work(struct work_param* param);

#endif /* WORK_H_ */
