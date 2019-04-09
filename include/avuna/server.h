//
// Created by p on 2/23/19.
//

#ifndef AVUNA_HTTPD_SERVER_H
#define AVUNA_HTTPD_SERVER_H

#include <avuna/pmem.h>
#include <avuna/list.h>
#include <avuna/queue.h>
#include <avuna/tls.h>
#include <avuna/log.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stdint.h>

#define BINDING_TCP4 0
#define BINDING_TCP6 1
#define BINDING_UNIX 2

#define BINDING_MODE_PLAINTEXT 1
#define BINDING_MODE_HTTPS 2
// #define BINDING_MODE_ADAPTIVE 3 // not implemented
#define BINDING_MODE_HTTP11_ONLY 4
#define BINDING_MODE_HTTP2_UPGRADABLE 8
#define BINDING_MODE_HTTP2_ONLY 16

struct server_binding {
    struct mempool* pool;
    uint8_t binding_type;
    union {
        struct sockaddr_in tcp4;
        struct sockaddr_in6 tcp6;
        struct sockaddr_un un;
    } binding;
    int fd;
    uint32_t mode;
    struct cert* ssl_cert;
    size_t conn_limit;
};

struct server_info {
    char* id;
    struct mempool* pool;
    struct list* bindings;
    struct list* vhosts;
    struct logsess* logsess;
    uint16_t max_worker_count;
    size_t max_post;
    struct queue* prepared_connections;
};

#endif //AVUNA_HTTPD_SERVER_H
