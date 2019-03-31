//
// Created by p on 2/10/19.
//

#ifndef AVUNA_HTTPD_PMEM_H
#define AVUNA_HTTPD_PMEM_H


// this memory pool is a lie, this is just allocation tracking for lazy deallocation -- not preallocation

#include <avuna/hash.h>
#include <avuna/list.h>

// single thread access only!
struct mempool {
    struct hashset* allocations;
    struct list* hooks;
};

struct mempool* mempool_new();

void pfree(struct mempool* pool);

void* pmalloc(struct mempool* pool, size_t size);

void* pcalloc(struct mempool* pool, size_t size);

void* prealloc(struct mempool* pool, void* ptr, size_t size);

void* pxfer(struct mempool* from, struct mempool* to, void* ptr);

void* pclaim(struct mempool* pool, void* ptr);

void* punclaim(struct mempool* pool, void* ptr);

void pprefree(struct mempool* pool, void* ptr);

void pprefree_strict(struct mempool* pool, void* ptr);

void phook(struct mempool* pool, void (* hook)(void* arg), void* arg);

void pchild(struct mempool* parent, struct mempool* child);

void pxfer_parent(struct mempool* current_parent, struct mempool* new_parent, struct mempool* child);

#endif //AVUNA_HTTPD_PMEM_H
