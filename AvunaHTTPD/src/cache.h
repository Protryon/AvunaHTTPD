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

#define CE_NONE 0
#define CE_GZIP 1

struct scache {
		char* rp;
		int ce;
		char etag[35];
		char* code;
		struct headers* headers;
		struct body* body;
};

struct cache {
		struct scache** scaches;
		size_t scache_size;
		pthread_rwlock_t scachelock;
};

struct scache* getSCache(struct cache* cache, char* rp, int ce);

int addSCache(struct cache* cache, struct scache* scache);

#endif /* CACHE_H_ */
