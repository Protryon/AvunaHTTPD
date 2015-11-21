/*
 * queue.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef QUEUE_H_
#define QUEUE_H_

#include <pthread.h>

struct collection {
		size_t size;
		size_t count;
		size_t capacity;
		size_t dsize;
		size_t rc;
		void** data;
		pthread_mutex_t data_mutex;
};

struct collection* new_collection(size_t capacity, size_t data_size);

int del_collection(struct collection* coll);

int add_collection(struct collection* coll, void* data);

int rem_collection(struct collection* coll, void* data);

#endif /* QUEUE_H_ */
