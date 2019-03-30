/*
 * util.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <avuna/pmem.h>
#include <sys/stat.h>
#include <stdlib.h>

void* xcopy(const void* ptr, size_t size, size_t expand, struct mempool* pool);

int recur_mkdir(const char* path, mode_t mode);

int memeq(const unsigned char* mem1, size_t mem1_size, const unsigned char* mem2, size_t mem2_size);

int memseq(const unsigned char* mem, size_t mem_size, const unsigned char c);

#endif /* UTIL_H_ */
