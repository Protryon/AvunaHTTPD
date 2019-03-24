/*
 * smem.c
 *
 *  Created on: Jul 24, 2016
 *      Author: root
 */

#include <stdlib.h>
#include "smem.h"
#include <stdio.h>

void* __smem_default_oom_callback(size_t size, void* cptr, int type) {
	printf("OOM!\n");
	exit (EXIT_FAILURE);
	return NULL;
}

void* (*__smem_oom_callback)(size_t size, void* cptr, int type) = (void*) __smem_default_oom_callback;

void smem_setOOMCallback(void* (*func)(size_t, void*, int)) {
	__smem_oom_callback = func;
}

void* smalloc(size_t size) {
	void* m = malloc(size);
	if (m == NULL) m = __smem_oom_callback(size, NULL, SMEM_CALLBACK_MALLOC);
	return m;
}

void* srealloc(void* ptr, size_t size) {
	void* m = realloc(ptr, size);
	if (m == NULL) m = __smem_oom_callback(size, ptr, SMEM_CALLBACK_REALLOC);
	return m;
}

void* scalloc(size_t size) {
	void* m = calloc(1, size);
	if (m == NULL) m = __smem_oom_callback(size, NULL, SMEM_CALLBACK_CALLOC);
	return m;
}
