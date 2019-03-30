/*
 * queue.c
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#include <avuna/llist.h>
#include <avuna/pmem.h>

struct llist* llist_new(struct mempool* pool) {
    struct llist* list = pcalloc(pool, sizeof(struct llist));
    list->pool = pool;
    return list;
}

int llist_free(struct llist* list) {
    pfree(list->pool);
}

struct llist_node* _llist_new_node(struct llist* llist, void* data) {
    struct llist_node* node = pcalloc(llist->pool, sizeof(struct llist_node));
    node->data = data;
    return node;
}

struct llist_node* llist_prepend(struct llist* llist, void* data) {
    struct llist_node* node = _llist_new_node(llist, data);
    node->next = llist->head;
    if (llist->head == NULL) {
        llist->head = node;
        llist->tail = node;
    } else {
        llist->head->prev = node;
    }
    llist->head = node;
    ++llist->size;
    return node;
}

struct llist_node* llist_append(struct llist* llist, void* data) {
    struct llist_node* node = _llist_new_node(llist, data);
    node->prev = llist->tail;
    if (llist->tail == NULL) {
        llist->head = node;
        llist->tail = node;
    } else {
        llist->tail->next = node;
    }
    llist->tail = node;
    ++llist->size;
    return node;
}

struct llist_node* llist_after(struct llist* llist, struct llist_node* node, void* data) {
    struct llist_node* new_node = _llist_new_node(llist, data);
    new_node->prev = node;
    new_node->next = node->next;
    node->next = new_node;
    if (new_node->next != NULL) new_node->next->prev = new_node;
    else llist->tail = new_node;
    ++llist->size;
    return new_node;
}

struct llist_node* llist_before(struct llist* llist, struct llist_node* node, void* data) {
    struct llist_node* new_node = _llist_new_node(llist, data);
    new_node->prev = node->prev;
    new_node->next = node;
    node->prev = new_node;
    if (new_node->prev != NULL) new_node->prev->next = new_node;
    else llist->head = new_node;
    ++llist->size;
    return new_node;
}

void llist_del(struct llist* llist, struct llist_node* node) {
    if (node == NULL) {
        return;
    }
    if (node->prev == NULL) {
        llist->head = node->next;
    } else {
        node->prev->next = node->next;
    }
    if (node->next == NULL) {
        llist->tail = node->prev;
    } else {
        node->next->prev = node->prev;
    }
    --llist->size;
    pprefree(llist->pool, node);
}
