//
// Created by p on 2/10/19.
//

#ifndef AVUNA_HTTPD_HEADERS_H
#define AVUNA_HTTPD_HEADERS_H

#include <stdlib.h>

// we don't use a hashmap as order is not entirely irrelevant
// we should use a linked hashmap in the future

struct headers {
    size_t count;
    size_t capacity;
    char** names;
    char** values;
    struct mempool* pool;
};

const char* header_get(const struct headers* headers, const char* name);

int header_set(struct headers* headers, const char* name, const char* value);

int header_add(struct headers* headers, const char* name, const char* value);

int header_tryadd(struct headers* headers, const char* name, const char* value);

int header_setoradd(struct headers* headers, const char* name, const char* value);

int header_parse(struct headers *headers, char *data, int mode, struct mempool *pool);

char* header_serialize(struct headers *headers, size_t *len);

#endif //AVUNA_HTTPD_HEADERS_H
