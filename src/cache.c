/*
 * cache.c
 *
 *  Created on: Nov 25, 2015
 *      Author: root
 */

#include <avuna/cache.h>

struct cache* cache_new(size_t max_size) {
    struct mempool* pool = mempool_new();
    struct cache* cache = pmalloc(pool, sizeof(struct cache));
    cache->pool = pool;
    cache->max_size = max_size;
    pthread_rwlock_init(&cache->scachelock, NULL);
    phook(pool, pthread_rwlock_destroy, &cache->scachelock);
    cache->entries = hashmap_new(128, pool);
    return cache;
}

struct scache* cache_get(struct cache* cache, char* request_path, int content_encoding) {
    pthread_rwlock_rdlock(&cache->scachelock);
    struct list* local_list = hashmap_get(cache->entries, request_path);
    if (local_list == NULL) {
        pthread_rwlock_unlock(&cache->scachelock);
        return NULL;
    }
    for (size_t i = 0; i < local_list->count; ++i) {
        struct scache* scache = local_list->data[i];
        if ((content_encoding == 1 || (content_encoding == scache->content_encoding))) {
            pthread_rwlock_unlock(&cache->scachelock);
            return scache;
        }
    }
    pthread_rwlock_unlock(&cache->scachelock);
    return NULL;
}

void cache_add(struct cache* cache, struct scache* scache) {
    pthread_rwlock_wrlock(&cache->scachelock);
    struct list* local_list = hashmap_get(cache->entries, scache->request_path);
    if (local_list == NULL) {
        local_list = list_new(8, cache->pool);
        hashmap_put(cache->entries, scache->request_path, local_list);
    }
    list_append(local_list, scache);
    pthread_rwlock_unlock(&cache->scachelock);
}

