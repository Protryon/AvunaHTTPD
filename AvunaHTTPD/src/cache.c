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

