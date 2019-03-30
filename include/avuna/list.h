/*
 * queue.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef LIST_H_
#define LIST_H_

#include <avuna/pmem.h>
#include <unistd.h>

struct list {
    size_t size;
    size_t count;
    size_t capacity;
    struct mempool* pool;
    void** data;
};

struct list* list_new(size_t initial_capacity, struct mempool* pool);

int list_free(struct list* list);

int list_add(struct list* list, void* data);

int list_find_remove(struct list* list, void* data);

#define ITER_LIST(list) for (size_t list_i = 0; list_i < list->count; ++list_i) { void* item = list->data[list_i];

#define ITER_LIST_END() }

#endif /* LIST_H_ */
