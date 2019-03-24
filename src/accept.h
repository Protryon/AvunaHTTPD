/*
 * accept.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef ACCEPT_H_
#define ACCEPT_H_

#include "config.h"
#include "list.h"
#include <sys/socket.h>
#include "work.h"
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <netinet/ip6.h>
#include "queue.h"
#include "http.h"
#include <stdint.h>
#include "pmem.h"
#include "server.h"
#include <stdint.h>
#include "buffer.h"

struct accept_param {
    struct server_info* server;
    struct server_binding* binding;
};

struct http2_stream {
    uint32_t id;
    unsigned char* http2_dataBuffer;
    size_t http2_dataBuffer_size;
    unsigned char* http2_headerBuffer;
    size_t http2_headerBuffer_size;
};

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
    struct buffer cache_buffer;
    int proto;
    struct http2_stream** http2_stream;
    size_t http2_stream_size;
    size_t nextStream;
    struct mempool* pool;
};

void run_accept(struct accept_param* param);

#endif /* ACCEPT_H_ */
