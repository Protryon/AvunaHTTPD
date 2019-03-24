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
#include "tls.h"

struct errpage {
	uint16_t code;
	char* page;
};

struct fcgi {
	socklen_t addrlen;
	struct sockaddr* addr;
	struct list* mimes;
	uint16_t req_id_counter;
};

struct vhost_htdocs {
	struct cache* cache;
	struct list* cache_types;
	uint8_t enableGzip;
	uint8_t scacheEnabled;
	size_t maxAge;
	size_t maxCache;
	char* htdocs;
	uint8_t symlock;
	uint8_t nohardlinks;
	uint32_t max_post;
	struct list* index;
	struct hashmap* error_pages;
	struct hashmap* fcgis;
};

struct vhost_rproxy {
	struct cache* cache;
	struct list* cache_types;
	uint8_t enableGzip;
	uint8_t scacheEnabled;
	size_t maxAge;
	size_t maxCache;
	struct sockaddr* fwaddr;
	socklen_t fwaddrlen;
	char* fwpath;
	struct headers* headers;
	struct hashset* dynamic_types;
	int xfor;
};

struct vhost_redirect {
	char* redir;
};

struct mountpoint {
	char* path;
	char* vhost;
};

struct vhost_mount {
	struct list* mounts;
	uint8_t keep_prefix;
};



struct vhost {
	uint8_t type;
	struct cert* ssl_cert;
	struct list* hosts;
	char* id;
	struct mempool* pool;
	union {
		struct vhost_htdocs htdocs;
		struct vhost_rproxy rproxy;
		struct vhost_redirect redirect;
		struct vhost_mount mount;
	} sub;
};

int domeq(const char* dom1, const char* dom2);

#endif /* VHOST_H_ */
