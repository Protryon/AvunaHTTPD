//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_VHOST_H
#define AVUNA_HTTPD_VHOST_H

#include "cache.h"
#include <sys/socket.h>
#include <stdint.h>
#include "tls.h"
#include "list.h"
#include "pmem.h"
#include "http.h"
#include "config.h"

struct hashmap* registered_vhost_types;

struct vhost_type {
    char* name;
    void (*load_config)(struct vhost* vhost, struct config_node* node);
    void (*handle_request)(struct vhost* vhost, struct request_session* rs);
    void* extra;
};

struct vhost {
    uint8_t type;
    struct cert* ssl_cert;
    struct list* hosts;
    char* id;
    struct mempool* pool;
    struct vhost_type* sub;
};

#endif //AVUNA_HTTPD_VHOST_H
