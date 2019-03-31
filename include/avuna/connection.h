//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_CONNECTION_H
#define AVUNA_HTTPD_CONNECTION_H

#include <avuna/pmem.h>
#include <avuna/tls.h>
#include <avuna/buffer.h>
#include <avuna/list.h>
#include <avuna/queue.h>
#include <avuna/http.h>
#include <avuna/server.h>
#include <openssl/ssl.h>
#include "buffer.h"
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <netinet/ip6.h>
#include <stdint.h>

struct conn;

struct sub_conn {
    struct conn* conn;
    struct mempool* pool;
    int fd;
    int tls;
    int tls_handshaked;
    SSL* tls_session;
    struct buffer read_buffer;
    struct buffer write_buffer;
    int tls_next_direction;
    int (*read)(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);
    void (*on_closed)(struct sub_conn* sub_conn);
    void* extra;
};

struct connection_manager;

struct conn {
    int fd;
    union {
        struct sockaddr_in6 tcp6;
        struct sockaddr_in tcp4;
    } addr;
    struct server_binding* incoming_binding;
    struct server_info* server;
    struct llist* sub_conns;
    struct mempool* pool;
    struct connection_manager* manager;
};

struct connection_manager {
    struct llist* pending_sub_conns;
};


#endif //AVUNA_HTTPD_CONNECTION_H
