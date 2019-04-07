/*
 * queue.c
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#include <avuna/queue.h>
#include <avuna/string.h>
#include <errno.h>

struct queue* queue_new(size_t capacity, int multithreaded, struct mempool* pool) {
    struct queue* queue = pmalloc(pool, sizeof(struct queue));
    queue->capacity = capacity;
    queue->data = pmalloc(pool, (capacity == 0 ? 16 : capacity) * sizeof(void*));
    queue->real_capacity = capacity == 0 ? 16 : 0;
    queue->start = 0;
    queue->end = 0;
    queue->size = 0;
    queue->multithreaded = multithreaded;
    queue->pool = pool;
    if (multithreaded) {
        if (pthread_mutex_init(&queue->data_mutex, NULL)) {
            if (pool == NULL) {
                free(queue->data);
                free(queue);
            }
            return NULL;
        }
        if (pthread_cond_init(&queue->out_cond, NULL)) {
            if (pool == NULL) {
                free(queue->data);
                free(queue);
                pthread_mutex_destroy(&queue->data_mutex);
            }
            return NULL;
        }
        if (pthread_cond_init(&queue->in_cond, NULL)) {
            if (pool == NULL) {
                free(queue->data);
                free(queue);
                pthread_mutex_destroy(&queue->data_mutex);
                pthread_cond_destroy(&queue->out_cond);
            }
            return NULL;
        }
        if (pool != NULL) {
            phook(pool, pthread_mutex_destroy, &queue->data_mutex);
            phook(pool, pthread_cond_destroy, &queue->out_cond);
            phook(pool, pthread_cond_destroy, &queue->in_cond);
        }
    }
    return queue;
}

int queue_free(struct queue* queue) {
    if (queue == NULL || queue->data == NULL || queue->pool != NULL) return -1;
    if (queue->multithreaded) {
        if (pthread_mutex_destroy(&queue->data_mutex)) return -1;
        if (pthread_cond_destroy(&queue->out_cond)) return -1;
        if (pthread_cond_destroy(&queue->in_cond)) return -1;
    }
    free(queue->data);
    queue->data = NULL;
    free(queue);
    return 0;
}

int queue_push(struct queue* queue, void* data) {
    if (queue->multithreaded) pthread_mutex_lock(&queue->data_mutex);
    if (queue->size == queue->real_capacity && queue->capacity == 0) {
        size_t orc = queue->real_capacity;
        queue->real_capacity += 1024 / sizeof(void*);
        void** ndata = pmalloc(queue->pool, queue->real_capacity * sizeof(void*));
        if (queue->start < queue->end) {
            memcpy(ndata, queue->data + queue->start, (queue->end - queue->start) * sizeof(void*));
        } else {
            memcpy(ndata, queue->data + queue->start, (orc - queue->start) * sizeof(void*));
            memcpy(ndata + (orc - queue->start), queue->data + queue->end, (queue->start - queue->end) * sizeof(void*));
        }
        pprefree(queue->pool, queue->data);
        queue->data = ndata;
    } else if (queue->capacity == 0) {
    } else {
        while (queue->size == queue->capacity) {
            if (!queue->multithreaded) return 1;
            pthread_cond_wait(&queue->in_cond, &queue->data_mutex);
        }
    }
    queue->data[queue->end++] = data;
    size_t rp = queue->capacity > 0 ? queue->capacity : queue->real_capacity;
    if (queue->end >= rp) {
        if (queue->end - rp == queue->start) {
            size_t orc = queue->real_capacity;
            queue->real_capacity += 1024 / sizeof(void*);
            void** ndata = pmalloc(queue->pool, queue->real_capacity * sizeof(void*));
            if (queue->start < queue->end) {
                memcpy(ndata, queue->data + queue->start, (queue->end - queue->start) * sizeof(void*));
            } else {
                memcpy(ndata, queue->data + queue->start, (orc - queue->start) * sizeof(void*));
                memcpy(ndata + (orc - queue->start), queue->data + queue->end,
                       (queue->start - queue->end) * sizeof(void*));
            }
            pprefree(queue->pool, queue->data);
            queue->data = ndata;
        } else queue->end -= rp;
    }
    queue->size++;
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
        pthread_cond_signal(&queue->out_cond);
    }
    return 0;
}

void queue_block(struct queue* queue) {
    if (queue->multithreaded) {
        pthread_mutex_lock(&queue->data_mutex);
        while (queue->size == 0) {
            pthread_cond_wait(&queue->out_cond, &queue->data_mutex);
        }
        pthread_mutex_unlock(&queue->data_mutex);
    }
}

void* queue_pop(struct queue* queue) {
    if (queue->multithreaded) {
        pthread_mutex_lock(&queue->data_mutex);
        while (queue->size == 0) {
            pthread_cond_wait(&queue->out_cond, &queue->data_mutex);
        }
    } else if (queue->size == 0) {
        return NULL;
    }
    void* data = queue->data[queue->start++];
    size_t rp = queue->capacity > 0 ? queue->capacity : queue->real_capacity;
    if (queue->start >= rp) {
        queue->start -= rp;
    }
    queue->size--;
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
        pthread_cond_signal(&queue->in_cond);
    }
    return data;
}

void* queue_index(struct queue* queue, size_t index) {
    if (queue->size < index) { // assuming atomic access
        return NULL;
    }
    if (queue->multithreaded) {
        pthread_mutex_lock(&queue->data_mutex);
    }
    index += queue->start;
    size_t rp = queue->capacity > 0 ? queue->capacity : queue->real_capacity;
    if (queue->start >= rp) {
        queue->start -= rp;
    }
    void* data = queue->data[index];
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
    }
    return data;
}

void* queue_maybepop(struct queue* queue) {
    if (queue->multithreaded) {
        pthread_mutex_lock(&queue->data_mutex);
        if (queue->size == 0) {
            pthread_mutex_unlock(&queue->data_mutex);
            return NULL;
        }
    } else if (queue->size == 0) {
        return NULL;
    }
    void* data = queue->data[queue->start++];
    size_t rp = queue->capacity > 0 ? queue->capacity : queue->real_capacity;
    if (queue->start >= rp) {
        queue->start -= rp;
    }
    queue->size--;
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
        pthread_cond_signal(&queue->in_cond);
    }
    return data;
}

void* queue_peek(struct queue* queue) {
    if (queue->multithreaded) {
        pthread_mutex_lock(&queue->data_mutex);
        while (queue->size == 0) {
            pthread_cond_wait(&queue->out_cond, &queue->data_mutex);
        }
    } else if (queue->size == 0) {
        return NULL;
    }
    void* data = queue->data[queue->start];
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
        pthread_cond_signal(&queue->in_cond);
    }
    return data;
}

void* queue_pop_timeout(struct queue* queue, struct timespec* abstime) {
    if (queue->multithreaded) {
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
    size_t rp = queue->capacity > 0 ? queue->capacity : queue->real_capacity;
    if (queue->start >= rp) {
        queue->start -= rp;
    }
    queue->size--;
    if (queue->multithreaded) {
        pthread_mutex_unlock(&queue->data_mutex);
        pthread_cond_signal(&queue->in_cond);
    }
    return data;
}
