//
// Created by p on 2/10/19.
//

#ifndef AVUNA_HTTPD_HEADERS_H
#define AVUNA_HTTPD_HEADERS_H

#include <avuna/pmem.h>
#include <avuna/hash.h>
#include <avuna/llist.h>
#include <stdlib.h>

struct header_entry {
    char* name;
    char* value;
    struct llist_node* map_node;
    struct llist_node* node;
};

struct headers {
    struct llist* header_list;
    struct hashmap* header_map;
    struct mempool* pool;
};

char* header_get(struct headers* headers, char* name);

int header_set(struct headers* headers, char* name, char* value);

int header_add(struct headers* headers, char* name, char* value);

int header_tryadd(struct headers* headers, char* name, char* value);

int header_setoradd(struct headers* headers, char* name, char* value);

struct headers* header_new(struct mempool* parent);

struct headers* header_parse(char* data, struct mempool* parent);

char* header_serialize(struct headers* headers, size_t* len);

#endif //AVUNA_HTTPD_HEADERS_H
