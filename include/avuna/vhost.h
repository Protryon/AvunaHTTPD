//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_VHOST_H
#define AVUNA_HTTPD_VHOST_H

#include <avuna/pmem.h>
#include <avuna/cache.h>
#include <avuna/tls.h>
#include <avuna/list.h>
#include <avuna/http.h>
#include <avuna/config.h>
#include <sys/socket.h>
#include <stdint.h>

struct hashmap* registered_vhost_types;

struct vhost;
struct request_session;

#define VHOST_ACTION_NONE 0
#define VHOST_ACTION_RESTART 1
#define VHOST_ACTION_NO_CONTENT_UPDATE 2

struct vhost_type {
    char* name;
    int (*load_config)(struct vhost* vhost, struct config_node* node);
    int (*handle_request)(struct request_session* rs); // returns a VHOST_ACTION_* value
    void* extra;
};

struct vhost {
    struct cert* ssl_cert;
    struct list* hosts;
    char* id;
    struct mempool* pool;
    struct vhost_type* sub;
};

#endif //AVUNA_HTTPD_VHOST_H
