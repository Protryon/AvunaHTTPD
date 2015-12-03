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

#define VHOST_HTDOCS 0
#define VHOST_RPROXY 1
#define VHOST_REDIRECT 2
#define VHOST_MOUNT 3

struct errpage {
		char* code;
		char* page;
};

struct fcgi {
		socklen_t addrlen;
		struct sockaddr* addr;
		size_t mime_count;
		char** mimes;
};

struct vhost_htdocs {
		struct cache cache;
		size_t cacheType_count;
		char** cacheTypes;
		int enableGzip;
		int scacheEnabled;
		size_t maxAge;
		char* htdocs;
		int symlock;
		int nohardlinks;
		size_t index_count;
		char** index;
		size_t errpage_count;
		struct errpage** errpages;
		size_t fcgi_count;
		struct fcgi** fcgis;
		int** fcgifds;
};

struct vhost_rproxy {
		struct cache cache;
		size_t cacheType_count;
		char** cacheTypes;
		int enableGzip;
		int scacheEnabled;
		size_t maxAge;
		struct sockaddr* fwaddr;
		socklen_t fwaddrlen;
		char* fwpath;
		struct headers* headers;
		size_t dmime_count;
		char** dmimes;
		int xfor;
};

struct vhost_redirect {
		char* redir;
};

struct vhmount {
		char* path;
		char* vh;
};

struct vhost_mount {
		struct vhmount* vhms;
		int vhm_count;
};

union vhost_sub {
		struct vhost_htdocs htdocs;
		struct vhost_rproxy rproxy;
		struct vhost_redirect redirect;
		struct vhost_mount mount;
};

struct vhost {
		int type;
		size_t host_count; // if 0, all hosts match
		char** hosts;
		char* id;
		union vhost_sub sub;
};

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
