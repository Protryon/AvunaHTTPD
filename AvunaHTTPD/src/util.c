/*
 * util.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "xstring.h"
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

void* xmalloc(size_t size) {
	void* m = malloc(size);
	if (m == NULL) {
		printf("Out of Memory!\n");
		exit(1);
	}
	return m;
}

void xfree(void* ptr) {
	free(ptr);
}

void* xcalloc(size_t size) {
	void* m = calloc(1, size);
	if (m == NULL) {
		printf("Out of Memory!\n");
		exit(1);
	}
	return m;
}

void* xrealloc(void* ptr, size_t size) {
	void* m = realloc(ptr, size);
	if (m == NULL) {
		printf("Out of Memory!\n");
		exit(1);
	}
	return m;
}

void* xcopy(void* ptr, size_t size, size_t expand) {
	void* alloc = xmalloc(size + expand);
	memcpy(alloc, ptr, size);
	return alloc;
}

int recur_mkdir(const char* path, mode_t mode) {
	char rp[PATH_MAX];
	realpath(path, rp);
	size_t pl = strlen(rp);
	char* pp[16];
	int ppi = 0;
	for (int i = 0; i < pl; i++) {
		if (rp[i] == '/') {
			if (ppi == 16) break;
			pp[ppi++] = &rp[i] + 1;
			rp[i] = 0;
		}
	}
	if (strlen(pp[ppi - 1]) == 0) ppi--;
	char vp[pl + 1];
	vp[pl] = 0;
	vp[0] = 0;
	for (int i = 0; i < ppi; i++) {
		strcat(vp, "/");
		strcat(vp, pp[i]);
		int r = mkdir(vp, mode);
		if (r == -1 && errno != EEXIST) {
			return -1;
		}
	}
	return 0;
}
