/*
 * util.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <sys/stat.h>

void* xmalloc(size_t size);

void xfree(void* ptr);

void* xcalloc(size_t size);

void* xrealloc(void* ptr, size_t size);

void* xcopy(void* ptr, size_t size, size_t expand);

int recur_mkdir(const char* path, mode_t mode);

#endif /* UTIL_H_ */
