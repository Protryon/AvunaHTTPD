/*
 * vhost.h
 *
 *  Created on: Dec 13, 2015
 *      Author: root
 */

#ifndef VHOST_H_
#define VHOST_H_

#define VHOST_HTDOCS 0
#define VHOST_RPROXY 1
#define VHOST_REDIRECT 2
#define VHOST_MOUNT 3

#include "cache.h"
#include <sys/socket.h>
#include <stdint.h>

struct errpage {
		uint16_t code;
		char* page;
};

struct fcgi {
		socklen_t addrlen;
		struct sockaddr* addr;
		size_t mime_count;
		char** mimes;
		uint16_t gc;
};

struct vhost_htdocs {
		struct cache cache;
		size_t cacheType_count;
		char** cacheTypes;
		int enableGzip;
		int scacheEnabled;
		size_t maxAge;
		size_t maxCache;
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
		size_t maxCache;
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
		int keep_prefix;
};

union vhost_sub {
		struct vhost_htdocs htdocs;
		struct vhost_rproxy rproxy;
		struct vhost_redirect redirect;
		struct vhost_mount mount;
};

struct vhost {
		int type;
		struct cert* cert;
		size_t host_count; // if 0, all hosts match
		char** hosts;
		char* id;
		union vhost_sub sub;
};

int domeq(const char* dom1, const char* dom2);

#endif /* VHOST_H_ */
