/*
 * cache.c
 *
 *  Created on: Nov 25, 2015
 *      Author: root
 */

#include "cache.h"
#include "xstring.h"
#include <stdlib.h>
#include "util.h"
#include <pthread.h>

struct scache* getSCache(struct cache* cache, char* rp, int ce) {
	pthread_rwlock_rdlock(&cache->scachelock);
	for (int i = 0; i < cache->scache_size; i++) {
		if (streq(cache->scaches[i]->rp, rp) && cache->scaches[i]->ce == ce) {
			struct scache* sc = cache->scaches[i];
			pthread_rwlock_unlock(&cache->scachelock);
			return sc;
		}
	}
	pthread_rwlock_unlock(&cache->scachelock);
	return NULL;
}

struct dcache* getDCache(struct cache* cache, char* rp, int ce, unsigned char* md5) {
	pthread_rwlock_rdlock(&cache->dcachelock);
	for (int i = 0; i < cache->dcache_size; i++) {
		if (streq(cache->dcaches[i]->scache.rp, rp) && cache->dcaches[i]->scache.ce == ce && memeq(md5, 16, cache->dcaches[i]->md5, 16)) {
			struct dcache* dc = cache->dcaches[i];
			pthread_rwlock_unlock(&cache->dcachelock);
			return dc;
		}
	}
	pthread_rwlock_unlock(&cache->dcachelock);
	return NULL;
}

int addSCache(struct cache* cache, struct scache* scache) {
	pthread_rwlock_wrlock(&cache->scachelock);
	if (cache->scaches == NULL) {
		cache->scaches = xmalloc(sizeof(struct scache*));
		cache->scache_size = 1;
	} else {
		cache->scaches = xrealloc(cache->scaches, sizeof(struct scache*) * ++cache->scache_size);
	}
	cache->scaches[cache->scache_size - 1] = scache;
	pthread_rwlock_unlock(&cache->scachelock);
	return 0;
}

int addDCache(struct cache* cache, struct dcache* dcache) {
	pthread_rwlock_wrlock(&cache->dcachelock);
	if (cache->dcaches == NULL) {
		cache->dcaches = xmalloc(sizeof(struct dcache*));
		cache->dcache_size = 1;
	} else {
		cache->dcaches = xrealloc(cache->dcaches, sizeof(struct dcache*) * ++cache->dcache_size);
	}
	cache->dcaches[cache->dcache_size - 1] = dcache;
	pthread_rwlock_unlock(&cache->dcachelock);
	return 0;
}

