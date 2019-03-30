//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_PROVIDER_H
#define AVUNA_HTTPD_PROVIDER_H

#include <avuna/pmem.h>
#include <avuna/http.h>
#include <avuna/hash.h>
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

struct provision {
    uint8_t type;
    union {
        struct {
            int stream_fd;
            void* extra;
            struct provision_data (*read)(struct provision* provision);
        } stream;
        struct provision_data data;
    } data;
    char* content_type;
    void* extra;
};

struct provider {
    char* name;
    struct mempool* pool;
    void (*load_config)(struct provider* provider, struct config_node* node);
    struct provision* (*provide_data)(struct provider* provider, struct request_session* rs);
    void* extra;
};

#endif //AVUNA_HTTPD_PROVIDER_H
