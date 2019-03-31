//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_PROVIDER_H
#define AVUNA_HTTPD_PROVIDER_H

#include <avuna/pmem.h>
#include <avuna/http.h>
#include <avuna/hash.h>
#include <avuna/config.h>
#include <stdint.h>
#include <stdlib.h>

struct hashmap* available_provider_types; // name -> struct provider* (name/extra is NULL)

struct hashmap* available_providers; // name -> struct provider*

#define PROVISION_DATA 0
#define PROVISION_STREAM 1

struct provision_data {
    void* data;
    size_t size;
};

struct provision;
struct request_session;

struct provision_stream {
    int stream_fd;
    void* extra;
    ssize_t known_length;
    ssize_t (*read)(struct provision* provision, struct provision_data* buffer); // -2 == no data, not broken, -1 = error, 0 = end of stream, > 0 = data returned
};

struct provision {
    uint8_t type;
    union {
        struct provision_stream stream;
        struct provision_data data;
    } data;
    char* content_type;
    void* extra;
    struct mempool* pool;
};

struct provider {
    char* name;
    struct mempool* pool;
    void (*load_config)(struct provider* provider, struct config_node* node);
    struct provision* (*provide_data)(struct provider* provider, struct request_session* rs);
    void* extra;
    struct list* mime_types;
};

ssize_t raw_stream_read(struct provision* provision, struct provision_data* buffer);

struct chunked_stream_extra {
    struct sub_conn* sub_conn;
    ssize_t remaining;
};

ssize_t chunked_read(struct provision* provision, struct provision_data* buffer);

#endif //AVUNA_HTTPD_PROVIDER_H
