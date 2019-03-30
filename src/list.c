/*
 * queue.c
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#include <avuna/list.h>
#include <avuna/pmem.h>
#include <errno.h>
#include <stdlib.h>

struct list* list_new(size_t initial_capacity, struct mempool* pool) {
    struct list* list = pmalloc(pool, sizeof(struct list));
    list->capacity = initial_capacity;
    list->data = pmalloc(pool, initial_capacity * sizeof(void*));
    list->size = 0;
    list->count = 0;
    list->pool = pool;
    return list;
}

int list_free(struct list* list) {
    if (list == NULL || list->data == NULL || list->pool != NULL) return -1;
    free(list->data);
    list->data = NULL;
    free(list);
    return 0;
}

int list_add(struct list* list, void* data) {
    for (int i = 0; i < list->size; i++) {
        if (list->data[i] == NULL) {
            list->count++;
            list->data[i] = data;
            return 0;
        }
    }
    if (list->size == list->capacity) {
        list->capacity *= 2;
        list->data = prealloc(list->pool, list->data, list->capacity * sizeof(void*));
    } else if (list->capacity > 0 && list->size == list->capacity) {
        errno = EINVAL;
        return -1;
    }
    list->data[list->size++] = data;
    list->count++;
    return 0;
}

int list_find_remove(struct list* list, void* data) {
    for (int i = 0; i < list->size; i++) {
        if (list->data[i] == data) {
            list->data[i] = NULL;
            list->count--;
            return 0;
        }
    }
    return -1;
}

