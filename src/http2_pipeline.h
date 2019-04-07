//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HTTP2_PIPELINE_H
#define AVUNA_HTTPD_HTTP2_PIPELINE_H

#include <avuna/http2.h>
#include <avuna/connection.h>

#define STREAM_IDLE 0
#define STREAM_RESERVED_LOCAL 1
#define STREAM_RESERVED_REMOTE 2
#define STREAM_OPEN 3
#define STREAM_HALF_CLOSED_LOCAL 4
#define STREAM_HALF_CLOSED_REMOTE 5
#define STREAM_CLOSED 6


struct http2_stream {
    struct mempool* pool;
    uint8_t state;
    uint8_t headers_finished;
    uint32_t identifier;
    struct buffer header_buffer;
    struct buffer data_buffer;
};

int receive_http2_frame(struct sub_conn* sub_conn, struct frame* frame);

#endif //AVUNA_HTTPD_HTTP2_PIPELINE_H
