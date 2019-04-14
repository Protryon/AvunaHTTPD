//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HTTP2_NETWORK_H
#define AVUNA_HTTPD_HTTP2_NETWORK_H

#include <avuna/hpack.h>
#include <avuna/http.h>
#include <avuna/pmem.h>
#include <avuna/http2.h>
#include <avuna/connection.h>
#include <stdint.h>

void http2_send_frame(struct sub_conn* sub_conn, struct frame* frame);

struct frame* http2_make_frame(struct mempool* parent, uint8_t type);

void http2_error(struct sub_conn* sub_conn, uint32_t error_code);

void http2_send_data(struct request_session* rs, uint8_t* data, size_t data_length, uint8_t terminate);

struct http2_server_extra {
    size_t our_max_frame_size;
    size_t other_max_frame_size;
    uint8_t* frame_buffer;
    struct llist* remote_idle_streams;
    struct hashmap* streams;
    uint32_t our_next_stream;
    uint32_t other_min_next_stream;
    int has_received_preface;
    struct hpack_ctx* recv_hpack_ctx;
    struct hpack_ctx* send_hpack_ctx;
};

int handle_http2_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);

int http2_stream_notify(struct request_session* rs);

#endif //AVUNA_HTTPD_HTTP2_NETWORK_H
