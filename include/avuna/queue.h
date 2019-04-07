/*
 * queue.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef OQUEUE_H_
#define OQUEUE_H_

#include <avuna/pmem.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct queue {
    size_t size;
    size_t capacity;
    size_t start;
    size_t end;
    size_t real_capacity;
    void** data;
    pthread_mutex_t data_mutex;
    pthread_cond_t in_cond;
    pthread_cond_t out_cond;
    int multithreaded;
    struct mempool* pool;
};

struct queue* queue_new(size_t capacity, int multithreaded, struct mempool* pool);

int queue_free(struct queue* queue);

int queue_push(struct queue* queue, void* data);

void queue_block(struct queue* queue);

void* queue_pop(struct queue* queue);

void* queue_index(struct queue* queue, size_t index);

void* queue_maybepop(struct queue* queue);

void* queue_peek(struct queue* queue);

void* queue_pop_timeout(struct queue* queue, struct timespec* abstime);

#endif /* OQUEUE_H_ */
