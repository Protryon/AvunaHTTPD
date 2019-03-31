//
// Created by p on 3/30/19.
//

#ifndef AVUNA_HTTPD_VHOST_HTDOCS_H
#define AVUNA_HTTPD_VHOST_HTDOCS_H

#include <avuna/vhost.h>
#include <avuna/cache.h>
#include <avuna/list.h>
#include <avuna/hash.h>
#include <stdint.h>

// common base for util functions
struct vhost_htbase {
    struct cache* cache;
    struct list* cache_types;
    uint8_t enableGzip;
    uint8_t scacheEnabled;
    size_t maxAge;
    size_t maxCache;
    struct hashmap* error_pages;
};

struct vhost_htdocs {
    struct vhost_htbase base;
    char* htdocs;
    uint8_t symlock;
    uint8_t nohardlinks;
    struct list* index;
    struct hashmap* providers; // mime type string -> struct provider*
};

#endif //AVUNA_HTTPD_VHOST_HTDOCS_H
