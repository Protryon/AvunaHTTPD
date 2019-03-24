//
// Created by p on 2/26/19.
//

#ifndef AVUNA_HTTPD_BUFFER_H
#define AVUNA_HTTPD_BUFFER_H

#include <stdint.h>
#include "pmem.h"
#include <stdlib.h>

struct buffer { // TODO: linked list of fixed arrays instead
    struct mempool* pool;
    uint8_t* buffer;
    size_t size;
    size_t capacity;
};

void buffer_init(struct buffer* buffer, struct mempool* pool, size_t capacity);

void buffer_ensure_total_capacity(struct buffer* buffer, size_t capacity);

void buffer_ensure_capacity(struct buffer* buffer, size_t capacity);

size_t buffer_consume(struct buffer* buffer, uint8_t** data);

#endif //AVUNA_HTTPD_BUFFER_H
