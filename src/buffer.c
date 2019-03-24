//
// Created by p on 2/26/19.
//

#include "buffer.h"
#include "pmem.h"

void buffer_init(struct buffer* buffer, struct mempool* pool, size_t capacity) {
    buffer->pool = pool;
    buffer->buffer = capacity == 0 ? NULL : pmalloc(pool, capacity);
    buffer->capacity = capacity;
    buffer->size = 0;
}

void buffer_ensure_total_capacity(struct buffer* buffer, size_t capacity) {
    if (buffer->capacity < capacity) {
        if (buffer->capacity < 1024) {
            buffer->capacity = 1024;
        }
        while (buffer->capacity < capacity) {
            buffer->capacity *= 2;
        }
        buffer->buffer = prealloc(buffer->pool, buffer->buffer, buffer->capacity);
    }
}

void buffer_ensure_capacity(struct buffer* buffer, size_t capacity) {
    capacity += buffer->size;
    if (buffer->capacity < capacity) {
        if (buffer->capacity < 1024) {
            buffer->capacity = 1024;
        }
        while (buffer->capacity < capacity) {
            buffer->capacity *= 2;
        }
        buffer->buffer = prealloc(buffer->pool, buffer->buffer, buffer->capacity);
    }
}

size_t buffer_consume(struct buffer* buffer, uint8_t** data) {
    *data = buffer->buffer;
    punclaim(buffer->pool, buffer->buffer);
    size_t s = buffer->size;
    pfree(buffer->pool);
    return s;
}