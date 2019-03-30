/*
 * util.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */
#include <avuna/util.h>
#include <avuna/string.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

void* xcopy(const void* ptr, size_t size, size_t expand, struct mempool* pool) {
    void* alloc = pmalloc(pool, size + expand);
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

int memeq(const unsigned char* mem1, size_t mem1_size, const unsigned char* mem2, size_t mem2_size) {
    if (mem1 == NULL || mem2 == NULL) return 0;
    if (mem1 == mem2 && mem1_size == mem2_size) return 1;
    if (mem1_size != mem2_size) return 0;
    for (int i = 0; i < mem1_size; i++) {
        if (mem1[i] != mem2[i]) {
            return 0;
        }
    }
    return 1;
}

int memseq(const unsigned char* mem, size_t mem_size, const unsigned char c) {
    if (mem == NULL) return 0;
    for (int i = 0; i < mem_size; i++) {
        if (mem[i] != c) {
            return 0;
        }
    }
    return 1;
}
