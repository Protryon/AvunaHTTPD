//
// Created by p on 4/6/19.
//

#include "http2_network.h"
#include "http2_pipeline.h"
#include <avuna/connection.h>
#include <avuna/http2.h>
#include <avuna/buffer.h>
#include <avuna/http_util.h>
#include <stdint.h>

const uint8_t* preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

int handle_http2_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    struct http2_server_extra* extra = sub_conn->extra;
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    if (!extra->has_received_preface) {
        if (sub_conn->read_buffer.size >= 24) {
            uint8_t maybe_preface[24];
            buffer_pop(&sub_conn->read_buffer, 24, maybe_preface);
            if (!memeq(maybe_preface, 24, preface, 24)) {
                return 1;
            }
            extra->has_received_preface = 1;
        }
    }
    while (sub_conn->read_buffer.size > 9) {
        uint8_t header[9];
        buffer_peek(&sub_conn->read_buffer, 9, header);
        uint32_t frame_size = (uint32_t) header[0] << 16 | (uint32_t) header[1] << 8 | (uint32_t) header[2];
        if (frame_size > extra->max_frame_size) {
            return 1;
        }
        if (sub_conn->read_buffer.size >= frame_size + 9) {
            buffer_pop(&sub_conn->read_buffer, frame_size + 9, extra->frame_buffer);
            struct mempool* frame_pool = mempool_new();
            pchild(sub_conn->pool, frame_pool);
            uint32_t error_code = 0;
            printf("try frame\n");
            struct frame* frame = parse_frame(frame_pool, extra->frame_buffer, frame_size, &error_code);
            printf("got frame %i\n", frame->type);
            if (receive_http2_frame(sub_conn, frame)) {
                return 1;
            }
        } else {
            break;
        }
    }
    return 0;
}