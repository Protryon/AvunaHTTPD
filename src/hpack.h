//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HPACK_H
#define AVUNA_HTTPD_HPACK_H

#include <avuna/queue.h>

struct hpack_entry {
    char* key;
    char* value;
};

struct hpack_entry static_entries[60];

struct hpack_ctx {
    struct queue* dynamic_table;
    size_t dynamic_size;
};

#endif //AVUNA_HTTPD_HPACK_H
