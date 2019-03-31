//
// Created by p on 2/26/19.
//

#include <avuna/buffer.h>
#include <string.h>

void buffer_init(struct buffer* buffer, struct mempool* pool) {
    buffer->pool = pool;
    buffer->buffers = llist_new(pool);
    buffer->size = 0;
}

void buffer_push(struct buffer* buffer, void* data, size_t size) {
    buffer->size += size;
    struct buffer_entry* entry = pmalloc(buffer->pool, sizeof(struct buffer_entry));
    entry->size = size;
    entry->data = data;
    entry->data_root = entry->data;
    llist_append(buffer->buffers, entry);
}

void buffer_skip(struct buffer* buffer, size_t size) {
    struct llist_node* node = buffer->buffers->head;
    if (size > buffer->size) {
        size = buffer->size;
    }
    buffer->size -= size;
    while (node != NULL && size > 0) {
        struct buffer_entry* entry = node->data;
        if (entry->size <= size) {
            size -= entry->size;
            struct llist_node* next = node->next;
            pprefree_strict(buffer->pool, entry->data_root);
            llist_del(buffer->buffers, node);
            node = next;
        } else {
            entry->data += size;
            entry->size -= size;
            size = 0;
            node = NULL;
        }
    }
}

size_t buffer_pop(struct buffer* buffer, size_t size, uint8_t* data) {
    struct llist_node* node = buffer->buffers->head;
    if (size > buffer->size) {
        size = buffer->size;
    }
    buffer->size -= size;
    size_t index = 0;
    while (node != NULL && size > 0) {
        struct buffer_entry* entry = node->data;
        if (entry->size <= size) {
            size -= entry->size;
            memcpy(data + index, entry->data, entry->size);
            index += entry->size;
            struct llist_node* next = node->next;
            pprefree_strict(buffer->pool, entry->data_root);
            llist_del(buffer->buffers, node);
            node = next;
        } else {
            memcpy(data + index, entry->data, size);
            index += size;
            entry->data += size;
            entry->size -= size;
            size = 0;
            node = NULL;
        }
    }
    return index;
}


size_t buffer_peek(struct buffer* buffer, size_t size, uint8_t* data) {
    struct llist_node* node = buffer->buffers->head;
    if (size > buffer->size) {
        size = buffer->size;
    }
    size_t index = 0;
    while (node != NULL && size > 0) {
        struct buffer_entry* entry = node->data;
        if (entry->size <= size) {
            size -= entry->size;
            memcpy(data + index, entry->data, entry->size);
            index += entry->size;
            node = node->next;
        } else {
            memcpy(data + index, entry->data, size);
            index += size;
            size = 0;
            node = NULL;
        }
    }
    return index;
}