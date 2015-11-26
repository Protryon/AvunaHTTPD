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

struct dcache {
		unsigned char md5[16];
		struct scache scache;
};

struct cache {
		struct scache** scaches;
		size_t scache_size;
		pthread_rwlock_t scachelock;
		struct dcache** dcaches;
		size_t dcache_size;
		pthread_rwlock_t dcachelock;
};

struct scache* getSCache(struct cache* cache, char* rp, int ce);

struct dcache* getDCache(struct cache* cache, char* rp, int ce, unsigned char* md5);

int addSCache(struct cache* cache, struct scache* scache);

int addDCache(struct cache* cache, struct dcache* dcache);

#endif /* CACHE_H_ */
