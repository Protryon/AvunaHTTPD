//
// Created by p on 2/10/19.
//

#include <avuna/pmem.h>
#include <avuna/hash.h>
#include "smem.h"

struct hook_entry {
    void (* hook)(void* arg);

    void* arg;
};

struct mempool* mempool_new() {
    struct mempool* pool = smalloc(sizeof(struct mempool));
    pool->allocations = hashset_new(16, NULL);
    pool->hooks = list_new(16, pool);
    return pool;
}

void pfree(struct mempool* pool) {
    if (pool == NULL) {
        return;
    }
    for (size_t i = 0; i < pool->hooks->count; ++i) {
        struct hook_entry* entry = pool->hooks->data[i];
        entry->hook(entry->arg);
    }
    ITER_SET(pool->allocations) {
        free(ptr_key);
        ITER_SET_END();
    }
    hashset_free(pool->allocations);
    free(pool);
}

void* pmalloc(struct mempool* pool, size_t size) {
    void* item = smalloc(size);
    if (pool != NULL) hashset_addptr(pool->allocations, item);
    return item;
}

void* pcalloc(struct mempool* pool, size_t size) {
    void* item = scalloc(size);
    if (pool != NULL) hashset_addptr(pool->allocations, item);
    return item;
}

void* prealloc(struct mempool* pool, void* ptr, size_t size) {
    void* item = srealloc(ptr, size);
    if (pool != NULL && item != ptr) {
        hashset_remptr(pool->allocations, ptr);
        hashset_addptr(pool->allocations, item);
    }
    return item;
}

void* pxfer(struct mempool* from, struct mempool* to, void* ptr) {
    if (from != NULL && ptr != NULL && hashset_hasptr(from->allocations, ptr)) {
        punclaim(from, ptr);
        pclaim(to, ptr);
    } else if (from == NULL) {
        pclaim(to, ptr);
    }
    return ptr;
}

void* pclaim(struct mempool* pool, void* ptr) {
    if (pool != NULL && ptr != NULL) hashset_addptr(pool->allocations, ptr);
    return ptr;
}

void* punclaim(struct mempool* pool, void* ptr) {
    if (pool != NULL && ptr != NULL) hashset_remptr(pool->allocations, ptr);
    return ptr;
}

void pprefree(struct mempool* pool, void* ptr) {
    if (pool != NULL && ptr != NULL && hashset_hasptr(pool->allocations, ptr)) {
        hashset_remptr(pool->allocations, ptr);
    }
    free(ptr);
}

void pprefree_strict(struct mempool* pool, void* ptr) {
    if (pool != NULL && ptr != NULL && hashset_hasptr(pool->allocations, ptr)) {
        hashset_remptr(pool->allocations, ptr);
        free(ptr);
    }
}


void phook(struct mempool* pool, void (* hook)(void* arg), void* arg) {
    struct hook_entry* entry = pmalloc(pool, sizeof(struct hook_entry));
    entry->hook = hook;
    entry->arg = arg;
    list_add(pool->hooks, entry);
}

struct _mempool_pair { // always allocated in child
    struct mempool* parent;
    struct mempool* child;
};

void _punhook_parent(struct _mempool_pair* pair) {
    for (size_t i = 0; i < pair->parent->hooks->count; ++i) {
        struct hook_entry* entry = (struct hook_entry*) pair->parent->hooks->data[i];
        if (entry->hook == pfree && entry->arg == pair->child) {
            entry->arg = NULL; // disables pfree call
        }
    }
}

void _prehook_child(struct mempool* child, struct mempool* new_parent) {
    for (size_t i = 0; i < child->hooks->count; ++i) {
        struct hook_entry* entry = (struct hook_entry*) child->hooks->data[i];
        if (entry->hook == _punhook_parent) {
            struct _mempool_pair* pair = entry->arg;
            pair->parent = new_parent;
            return;
        }
    }
}

void pchild(struct mempool* parent, struct mempool* child) {
    phook(parent, pfree, child);
    struct _mempool_pair* pair = pmalloc(child, sizeof(struct _mempool_pair));
    pair->child = child;
    pair->parent = parent;
    phook(child, _punhook_parent, pair);
}

void pxfer_parent(struct mempool* current_parent, struct mempool* new_parent, struct mempool* child) {
    struct _mempool_pair unhook;
    unhook.parent = current_parent;
    unhook.child = child;
    _punhook_parent(&unhook);
    _prehook_child(child, new_parent);
    phook(new_parent, pfree, child);
}