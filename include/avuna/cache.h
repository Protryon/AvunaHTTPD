/*
 * cache.h
 *
 *  Created on: Nov 25, 2015
 *      Author: root
 */

#ifndef CACHE_H_
#define CACHE_H_

#include <avuna/pmem.h>
#include <avuna/list.h>
#include <avuna/hash.h>
#include <avuna/provider.h>
#include <stdlib.h>
#include <pthread.h>

struct scache {
    char* request_path;
    int content_encoding;
    char etag[35];
    char* code;
    struct headers* headers;
    struct provision* body;
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
