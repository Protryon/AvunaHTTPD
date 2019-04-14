//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HPACK_H
#define AVUNA_HTTPD_HPACK_H

#include <avuna/queue.h>
#include <avuna/pmem.h>
#include <avuna/hash.h>
#include <avuna/headers.h>
#include <avuna/llist.h>

struct hpack_entry {
    char* key;
    char* value;
    size_t size;
    size_t push_index;
    struct llist* containing_lookup_list;
    struct llist_node* lookup_node;
};

struct hpack_entry static_entries[61];

struct hashmap* static_entry_map;

struct hpack_ctx {
    struct mempool* pool;
    struct hashmap* lookup_map;
    struct queue* dynamic_table;
    size_t dynamic_size;
    size_t max_dynamic_size;
    size_t current_max_dynamic_size;
    size_t push_index;
};

struct hpack_ctx* hpack_init(struct mempool* pool, size_t max_dynamic_size);

int hpack_decode(struct headers* headers, struct hpack_ctx* ctx, struct mempool* pool, uint8_t* data, size_t data_length);

uint8_t* hpack_encode(struct hpack_ctx* ctx, struct mempool* pool, struct headers* headers, size_t* out_length);

#endif //AVUNA_HTTPD_HPACK_H
