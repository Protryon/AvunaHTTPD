/*
 * queue.c
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#include "oqueue.h"

#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "xstring.h"
#include <stdlib.h>
#include "smem.h"

struct queue* new_queue(size_t capacity, int mt) {
	struct queue* queue = smalloc(sizeof(struct queue));
	queue->capacity = capacity;
	queue->data = smalloc((capacity == 0 ? 1 : capacity) * sizeof(void*));
	queue->rc = capacity == 0 ? 1 : 0;
	queue->start = 0;
	queue->end = 0;
	queue->size = 0;
	queue->mt = mt;
	if (mt) {
		if (pthread_mutex_init(&queue->data_mutex, NULL)) {
			free(queue->data);
			queue->data = NULL;
			free(queue);
			return NULL;
		}
		if (pthread_cond_init(&queue->out_cond, NULL)) {
			free(queue->data);
			queue->data = NULL;
			pthread_mutex_destroy(&queue->data_mutex);
			free(queue);
			return NULL;
		}
		if (pthread_cond_init(&queue->in_cond, NULL)) {
			free(queue->data);
			queue->data = NULL;
			pthread_mutex_destroy(&queue->data_mutex);
			pthread_cond_destroy(&queue->out_cond);
			free(queue);
			return NULL;
		}
	}
	return queue;
}

int del_queue(struct queue* queue) {
	if (queue == NULL || queue->data == NULL) return -1;
	if (queue->mt) {
		if (pthread_mutex_destroy(&queue->data_mutex)) return -1;
		if (pthread_cond_destroy(&queue->out_cond)) return -1;
		if (pthread_cond_destroy(&queue->in_cond)) return -1;
	}
	free(queue->data);
	queue->data = NULL;
	free(queue);
	return 0;
}

int add_queue(struct queue* queue, void* data) {
	if (queue->mt) pthread_mutex_lock(&queue->data_mutex);
	if (queue->size == queue->rc && queue->capacity == 0) {
		size_t orc = queue->rc;
		queue->rc += 1024 / sizeof(void*);
		void** ndata = smalloc(queue->rc * sizeof(void*));
		if (queue->start < queue->end) {
			memcpy(ndata, queue->data + queue->start, (queue->end - queue->start) * sizeof(void*));
		} else {
			memcpy(ndata, queue->data + queue->start, (orc - queue->start) * sizeof(void*));
			memcpy(ndata + (orc - queue->start), queue->data + queue->end, (queue->start - queue->end) * sizeof(void*));
		}
		free(queue->data);
		queue->data = ndata;
	} else if (queue->capacity == 0) {
	} else {
		while (queue->size == queue->capacity) {
			if (!queue->mt) return 1;
			pthread_cond_wait(&queue->in_cond, &queue->data_mutex);
		}
	}
	queue->data[queue->end++] = data;
	size_t rp = queue->capacity > 0 ? queue->capacity : queue->rc;
	if (queue->end >= rp) {
		if (queue->end - rp == queue->start) {
			size_t orc = queue->rc;
			queue->rc += 1024 / sizeof(void*);
			void** ndata = smalloc(queue->rc * sizeof(void*));
			if (queue->start < queue->end) {
				memcpy(ndata, queue->data + queue->start, (queue->end - queue->start) * sizeof(void*));
			} else {
				memcpy(ndata, queue->data + queue->start, (orc - queue->start) * sizeof(void*));
				memcpy(ndata + (orc - queue->start), queue->data + queue->end, (queue->start - queue->end) * sizeof(void*));
			}
			free(queue->data);
			queue->data = ndata;
		} else queue->end -= rp;
	}
	queue->size++;
	if (queue->mt) {
		pthread_mutex_unlock(&queue->data_mutex);
		pthread_cond_signal(&queue->out_cond);
	}
	return 0;
}

void* pop_queue(struct queue* queue) {
	if (queue->mt) {
		pthread_mutex_lock(&queue->data_mutex);
		while (queue->size == 0) {
			pthread_cond_wait(&queue->out_cond, &queue->data_mutex);
		}
	} else if (queue->size == 0) {
		return NULL;
	}
	void* data = queue->data[queue->start++];
	size_t rp = queue->capacity > 0 ? queue->capacity : queue->rc;
	if (queue->start >= rp) {
		queue->start -= rp;
	}
	queue->size--;
	if (queue->mt) {
		pthread_mutex_unlock(&queue->data_mutex);
		pthread_cond_signal(&queue->in_cond);
	}
	return data;
}

void* timedpop_queue(struct queue* queue, struct timespec* abstime) {
	if (queue->mt) {
		pthread_mutex_lock(&queue->data_mutex);
		while (queue->size == 0) {
			int x = pthread_cond_timedwait(&queue->out_cond, &queue->data_mutex, abstime);
			if (x) {
				pthread_mutex_unlock(&queue->data_mutex);
				errno = x;
				return NULL;
			}
		}
	} else if (queue->size == 0) {
		return NULL;
	}
	void* data = queue->data[queue->start++];
	size_t rp = queue->capacity > 0 ? queue->capacity : queue->rc;
	if (queue->start >= rp) {
		queue->start -= rp;
	}
	queue->size--;
	if (queue->mt) {
		pthread_mutex_unlock(&queue->data_mutex);
		pthread_cond_signal(&queue->in_cond);
	}
	return data;
}
