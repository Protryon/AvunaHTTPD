/*
 * queue.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef LLIST_H_
#define LLIST_H_

#include <avuna/pmem.h>
#include <unistd.h>

struct llist_node {
    void* data;
    struct llist_node* next;
    struct llist_node* prev;
};

struct llist {
    size_t size;
    struct mempool* pool;
    struct llist_node* head;
    struct llist_node* tail;
};

struct llist* llist_new(struct mempool* pool);

int llist_free(struct llist* list);

struct llist_node* llist_prepend(struct llist* llist, void* data);

struct llist_node* llist_append(struct llist* llist, void* data);

struct llist_node* llist_after(struct llist* llist, struct llist_node* node, void* data);

struct llist_node* llist_before(struct llist* llist, struct llist_node* node, void* data);

void llist_del(struct llist* llist, struct llist_node* node);

#define ITER_LLIST(list, value) for (struct llist_node* node = list->head; node != NULL; node = node->next) { void* value = node->data;

#define ITER_LLIST_END() }

#endif /* LIST_H_ */
