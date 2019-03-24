/*
 * cache.h
 *
 *  Created on: Nov 25, 2015
 *      Author: root
 */

#ifndef CACHE_H_
#define CACHE_H_

#include <stdlib.h>
#include <pthread.h>
#include "pmem.h"
#include "list.h"
#include "hash.h"

#define CE_NONE 0
#define CE_GZIP 1

struct scache {
		char* request_path;
		int content_encoding;
		char etag[35];
		char* code;
		struct headers* headers;
		struct body* body;
		size_t size;
		struct mempool* pool;
};

struct cache {
		struct mempool* pool;
		struct hashmap* entries; // request_path -> list of scache
		pthread_rwlock_t scachelock;
		size_t max_size;
};

struct cache* cache_new(size_t max_size);

struct scache* cache_get(struct cache* cache, char* request_path, int content_encoding);

void cache_add(struct cache* cache, struct scache* scache);

#endif /* CACHE_H_ */
