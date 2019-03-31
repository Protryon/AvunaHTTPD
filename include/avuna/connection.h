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

struct sub_conn {
    int fd;
    int tls;
    int tls_handshaked;
    SSL* tls_session;
    struct buffer read_buffer;
    struct buffer write_buffer;
    int tls_next_direction;
};

struct conn {
    int fd;
    union {
        struct sockaddr_in6 tcp6;
        struct sockaddr_in tcp4;
    } addr;
    struct server_binding* incoming_binding;
    struct server_info* server;
    struct sub_conn* conn;
    struct sub_conn* forward_conn;
    size_t post_left;
    struct request_session* currently_posting;
    struct queue* fw_queue;
    int stream_fd;
    int stream_type;
    size_t stream_len;
    size_t streamed;
    struct request_session* forwarding_request;
    MD5_CTX* stream_md5;
    size_t nextStream;
    struct mempool* pool;
};

#endif //AVUNA_HTTPD_CONNECTION_H
