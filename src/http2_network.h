//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HTTP2_NETWORK_H
#define AVUNA_HTTPD_HTTP2_NETWORK_H

#include <avuna/http.h>
#include <avuna/connection.h>
#include <stdint.h>

struct http2_server_extra {
    size_t max_frame_size;
    uint8_t* frame_buffer;
    struct llist* remote_idle_streams;
    struct hashmap* streams;
    uint32_t our_next_stream;
    uint32_t other_min_next_stream;
    int has_received_preface;
};

int handle_http2_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);


#endif //AVUNA_HTTPD_HTTP2_NETWORK_H
