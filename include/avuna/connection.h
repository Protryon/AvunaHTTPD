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
#include <avuna/log.h>
#include <avuna/http.h>
#include <avuna/server.h>
#include <avuna/buffer.h>
#include <openssl/ssl.h>
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
    int write_available;
    int (*read)(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);
    void (*on_closed)(struct sub_conn* sub_conn);
    void* extra;
    int safe_close; // to allow closing when there might be pending events
    int (*notifier)(struct request_session* rs); // used for streams
};

struct connection_manager;

struct conn {
    union {
        struct sockaddr_in6 tcp6;
        struct sockaddr_in tcp4;
    } addr;
    struct server_binding* incoming_binding;
    struct server_info* server;
    struct llist* sub_conns;
    struct mempool* pool;
    struct connection_manager* manager;
    void* vhost_extra;
};

struct connection_manager {
    struct llist* pending_sub_conns;
};

int configure_fd(struct logsess* logger, int fd, int is_tcp);

void trigger_write(struct sub_conn* sub_conn);

#endif //AVUNA_HTTPD_CONNECTION_H
