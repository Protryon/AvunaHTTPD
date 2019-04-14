/*
 * http2.h
 *
 *  Created on: Dec 13, 2015
 *      Author: root
 */

#ifndef HTTP2_H_
#define HTTP2_H_

#include <avuna/connection.h>
#include <avuna/pmem.h>
#include <avuna/buffer.h>
#include <stdint.h>
#include <unistd.h>

#define FRAME_DATA_ID 0
#define FRAME_HEADERS_ID 1
#define FRAME_PRIORITY_ID 2
#define FRAME_RST_STREAM_ID 3
#define FRAME_SETTINGS_ID 4
#define FRAME_PUSH_PROMISE_ID 5
#define FRAME_PING_ID 6
#define FRAME_GOAWAY_ID 7
#define FRAME_WINDOW_UPDATE_ID 8
#define FRAME_CONTINUATION_ID 9

#define HTTP2_NO_ERROR 0
#define HTTP2_PROTOCOL_ERROR 1
#define HTTP2_INTERNAL_ERROR 2
#define HTTP2_FLOW_CONTROL_ERROR 3
#define HTTP2_SETTINGS_TIMEOUT 4
#define HTTP2_STREAM_CLOSED 5
#define HTTP2_FRAME_SIZE_ERROR 6
#define HTTP2_REFUSED_STREAM 7
#define HTTP2_CANCEL 8
#define HTTP2_COMPRESSION_ERROR 9
#define HTTP2_CONNECT_ERROR 10
#define HTTP2_ENHANCE_YOUR_CALM 11
#define HTTP2_INADEQUATE_SECURITY 12;
#define HTTP2_HTTP_1_1_REQUIRED 13;

#define HTTP2_SETTINGS_HEADER_TABLE_SIZE 0x1
#define HTTP2_SETTINGS_ENABLE_PUSH 0x2
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 0x4
#define HTTP2_SETTINGS_MAX_FRAME_SIZE 0x5
#define HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 0x6

struct frame_data {
    uint8_t* data;
    size_t data_length;
};

struct frame_headers {
    uint8_t exclusive;
    uint32_t stream_dependency;
    uint8_t weight;
    uint8_t* data; // TODO: hpack type
    size_t data_length;
};

struct frame_priority {
    uint8_t exclusive;
    uint32_t stream_dependency;
    uint8_t weight;
};

struct frame_rst_stream {
    uint32_t error_code;
};

struct frame_settings {
    size_t entry_count;
    struct {
        uint16_t key;
        uint32_t value;
    } __attribute__((packed))* entries;
};

struct frame_push_promise {
    uint32_t stream_id;
    uint8_t* data;
    size_t data_length;
};

struct frame_ping {
    uint64_t data;
};

struct frame_goaway {
    uint32_t last_stream_id;
    uint32_t error_code;
    uint8_t* data;
};

struct frame_window_update {
    uint32_t increment;
};

struct frame_continuation {
    uint8_t* data;
    size_t data_length;
};

union uframe {
    struct frame_data data;
    struct frame_headers headers;
    struct frame_priority priority;
    struct frame_rst_stream rst_stream;
    struct frame_settings settings;
    struct frame_push_promise push_promise;
    struct frame_ping ping;
    struct frame_goaway goaway;
    struct frame_window_update window_update;
    struct frame_continuation continuation;
};

struct frame {
    struct mempool* pool;
    // length is implicit
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    union uframe data;
};

struct frame* parse_frame(struct mempool* pool, uint8_t* data, size_t length, uint32_t* error_code);

int serialize_frame(struct frame* frame, struct buffer* buffer, uint8_t padding);

#endif /* HTTP2_H_ */
