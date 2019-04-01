//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_MODULE_H
#define AVUNA_HTTPD_MODULE_H

#include <avuna/pmem.h>
#include <avuna/hash.h>
#include <avuna/config.h>
#include <stdint.h>

struct hashmap* loaded_modules;

// modules add providers, provider types, and vhost types
struct module {
    struct mempool* pool;
    void* handle;
    char* name;
    void* extra;
    void (*initialize)(struct module* module);
    void (*uninitialize)(struct module* module);
};

#endif //AVUNA_HTTPD_MODULE_H
