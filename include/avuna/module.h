//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_MODULE_H
#define AVUNA_HTTPD_MODULE_H

#include <stdint.h>
#include "pmem.h"
#include "config.h"

struct hashmap* modules;

// modules add providers, provider types, and vhost types
struct module {
    struct mempool* pool;
    char* name;
    void* extra;
    void (*initialize)(struct module* module, struct config_node* node);
    void (*uninitialize)(struct module* module);
};

#endif //AVUNA_HTTPD_MODULE_H
