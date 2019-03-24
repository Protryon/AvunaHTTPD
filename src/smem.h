/*
 * smem.h
 *
 *  Created on: Jul 24, 2016
 *      Author: root
 */

#ifndef SMEM_H_
#define SMEM_H_

#define SMEM_CALLBACK_MALLOC 0
#define SMEM_CALLBACK_REALLOC 1
#define SMEM_CALLBACK_CALLOC 2

#include <stdlib.h>

//example: void* __smem_default_oom_callback(size_t size, void* cptr, int type)
void smem_setOOMCallback(void* (* func)(size_t, void*, int));

void* smalloc(size_t size);

void* srealloc(void* ptr, size_t size);

void* scalloc(size_t size);

#endif /* SMEM_H_ */
